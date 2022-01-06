import aiohttp
import asyncio
import itertools
import signal
import sys
import os

import traceback

from .main import DomiOwned
from .tlsadapter import get_ssl_context

class CommandScan(DomiOwned):

    def commandscan(self, nsf):
        """
        Scan all available commands for the specified NSF.
        """
        self.check_access(self.username, self.password)

        # Build directory list
        commands = self.build_commands_list()

        self.enum_commands(commands, nsf)

    def build_commands_list(self):
        """
        Create list of Domino NSF commands to enumerate.
        """
        commands = []

        commands = commands + open(os.path.abspath('./domi_owned/data/commands/domino_agent_commands.txt'), 'r').readlines()
        commands = commands + open(os.path.abspath('./domi_owned/data/commands/domino_database_commands.txt'), 'r').readlines()
        commands = commands + open(os.path.abspath('./domi_owned/data/commands/domino_document_commands.txt'), 'r').readlines()
        commands = commands + open(os.path.abspath('./domi_owned/data/commands/domino_form_commands.txt'), 'r').readlines()
        commands = commands + open(os.path.abspath('./domi_owned/data/commands/domino_navigator_commands.txt'), 'r').readlines()
        commands = commands + open(os.path.abspath('./domi_owned/data/commands/domino_view_commands.txt'), 'r').readlines()

        return commands

    def signal_handler(self, commands):
        """
        Gracefully handle exiting enumeration.
        """
        self.logger.debug('Got Ctrl-C, stopping all tasks...')
        for task in asyncio.Task.all_tasks():
            task.cancel()

    def enum_commands(self, commands, nsf):
        """
        Execute the requests for the enumeration and handle authentication.
        """
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGINT, self.signal_handler)

        if self.username and self.auth_type == 'basic':
            client = aiohttp.ClientSession(headers=self.utilities.HEADERS, auth=aiohttp.BasicAuth(self.username, self.password), loop=loop, connector=aiohttp.TCPConnector(ssl=get_ssl_context(not self.session.verify)))

        elif self.auth_type == 'form':
            # Check if cookies or SSO are being used for authentication
            if 'DomAuthSessId' in self.session.cookies:
                session_id = dict(DomAuthSessId=self.session.cookies['DomAuthSessId'])
            elif 'LtpaToken' in self.session.cookies:
                session_id = dict(LtpaToken=self.session.cookies['LtpaToken'])
            else:
                session_id = None

            client = aiohttp.ClientSession(headers=self.utilities.HEADERS, cookies=session_id, loop=loop, connector=aiohttp.TCPConnector(ssl=get_ssl_context(not self.session.verify)))

        else:
            client = aiohttp.ClientSession(headers=self.utilities.HEADERS, loop=loop, connector=aiohttp.TCPConnector(ssl=get_ssl_context(not self.session.verify)))

        try:
            task = loop.create_task(self.query(client, commands, nsf))
            loop.run_until_complete(task)
            loop.close()
        except asyncio.CancelledError:
            sys.exit()
        except Exception as error:
            self.logger.error('An error occurred while enumerating Domino NSF commands')
            self.logger.error(error)
            traceback.print_exc()
            sys.exit()

    async def query(self, session, commands, nsf):
        """
        Build asynchronous requests.
        """
        await asyncio.gather(*[self.get(session, command.strip(), nsf) for command in commands])
        await session.close()

    async def get(self, session, command, nsf):
        """
        Request account URL and parse response.
        """
        url = '{}/{}{}'.format(self.url, nsf, command)

        async with session.get(url, compress=True) as response:
            if self.auth_type == 'form' and self.utilities.FORM_REGEX.search(await response.text()):
                self.logger.warning("Form Auth - {0}".format(url))
                return
            if response.status == 200:
                self.logger.info("200 - {0}".format(url))
            elif response.status == 401:
                self.logger.warning("401 - {0}".format(url))
            else:
                return
