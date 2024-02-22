import re
import discord
import os
import random
import requests
import shlex
import subprocess
import time
import sys
import asyncio 
import traceback

from discord import app_commands
from discord.ext import commands, tasks
from asyncio.subprocess import PIPE, STDOUT
from urllib.parse import urlparse
from os.path import expanduser

#guild_id = "645718647905583128"
#GUILD = discord.Object(id=guild_id)

# Load environment variables
TOKEN = os.getenv('TOKEN')

if not TOKEN:
    print("Error: Discord bot token (TOKEN) not provided in environment variables.", file=sys.stderr)
    sys.exit(1)

ARACHNI_LOC = os.getenv('ARACHNI_LOC', '/usr/local/src/arachni/bin/arachni')
ARACHNI_REPORTER_LOC = os.getenv('ARACHNI_REPORTER_LOC', '/usr/local/src/arachni/bin/arachni_reporter')
DNSRECON_LOC = os.getenv('DNSRECON_LOC', '/usr/local/src/dnsrecon/dnsrecon.py')
SQLMAP_LOC = os.getenv('SQLMAP_LOC', '/usr/local/src/sqlmap/sqlmap.py')
DIRB_LOC = os.getenv('DIRB_LOC', 'dirb')
NMAP_LOC = os.getenv('NMAP_LOC', 'nmap')

class DiscordBot(discord.Client):
    def __init__(self, *, intents: discord.Intents, heartbeat_timeout: int = 35):
        super().__init__(intents=intents, heartbeat_timeout=heartbeat_timeout)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        pass
        #self.tree.copy_global_to(guild=GUILD)
        #await self.tree.sync(guild=GUILD)

intents = discord.Intents.all()
intents.messages = True

client = DiscordBot(intents=intents, heartbeat_timeout=35)

@tasks.loop(seconds=10)
async def consumer():
    while True:
        if not await consumer_dowork():
            if g_channel is not None:
                await g_queue.put(g_bug_finder.attackrandom())
        await asyncio.sleep(1)

async def consumer_dowork():
    try:
        task = await client.wait_for(g_queue.get(), timeout=1.0)
        await task
        return True
    except asyncio.TimeoutError:
        return False

async def create_initial_embed(message_ctx, description, title=None, icon=None, author=None):
    embed = discord.Embed(title=title, description=f'{description}')
    if author is None:
        author = message_ctx.user.display_name
    embed.set_author(name=author, icon_url=icon)
    #embed.set_thumbnail(url=message_ctx.user.avatar.url)
    return embed

async def send_channel_msg(message_ctx, txt, file_attach=[], followup=True):
    try:
        channel = message_ctx.channel
        print("[I] calling send_channel_msg() with %s" % txt)
        max_size = 2000
        embeds = []

        if message_ctx.client.user.avatar:
            avatar_url = message_ctx.client.user.avatar.url
        elif message_ctx.user.avatar:
            avatar_url = message_ctx.user.avatar.url
        else:
            avatar_url = None

        if len(txt) > max_size:
            output_msg = ""
            quotes = False
            for line in txt.splitlines(keepends=True):
                if (len(output_msg) + len(line)) > (max_size-8):
                    if quotes is True:
                        output_msg += "\n```"

                    if output_msg:
                        embed = await create_initial_embed(message_ctx, output_msg, "", author=message_ctx.client.user.name, icon=avatar_url)
                        embeds.append(embed)
                        output_msg = ""

                        if quotes is True:
                            output_msg += "```\n"

                if '```' in line and quotes is False:
                    quotes = True
                elif '```' in line and quotes is True:
                    quotes = False

                output_msg += "%s" % line
            if output_msg:
                embed = await create_initial_embed(message_ctx, output_msg, "", author=message_ctx.client.user.name, icon=avatar_url)
                embeds.append(embed)
        else:
            if txt:
                embed = await create_initial_embed(message_ctx, txt, "", author=message_ctx.client.user.name, icon=avatar_url)
                embeds.append(embed)

        if not followup:
            await message_ctx.response.send_message(content="", embeds=embeds, files=file_attach)
        else:
            await message_ctx.followup.send(content="", embeds=embeds, files=file_attach)
      
        return True
    except Exception as e:
        print('[E]', traceback.format_exc())
        return False

async def changestatus(message_ctx: discord.Interaction, action=None, domain=None):
    try:
        if domain is None and action is None:
            await client.change_presence(activity=None)
            return True
        if action is None:
            action="Hacking"
        await client.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="%s %s" % (action, domain)))
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        return False

@client.tree.command(description='Runs dnsrecon.py to enumerate subdomains on the provided hostname')
@app_commands.describe(
        domain='Host to run dnsrecon.py on (syntax: /dns_recon example.com).',
)
async def dns_recon(message_ctx: discord.Interaction, domain: str, followup: bool=False):
    try:
        channel = message_ctx.channel
        await send_channel_msg(message_ctx, '[I] Scanning for subdomains for `%s`' % domain, followup=followup)
        await changestatus(message_ctx, "dnsrecon", domain)
        subdomains = await g_bug_finder.dns_recon(domain)
        if not len(subdomains):
            await send_channel_msg(message_ctx, "[I] No subdomains found enumerating `*.%s`" % domain, followup=True)
            return {}

        msg = "[I] Found the following domains:\n"
        msg += "```"
        for domain,ip in subdomains.items():
            msg += "\t%s\n" % domain
        msg += "```"
        await changestatus(message_ctx)
        await send_channel_msg(message_ctx, msg, followup=True)
        return subdomains
    except Exception as e:
        await changestatus(message_ctx)
        print(e)
        print(traceback.format_exc())
        return {}

@client.tree.command(description='Runs a nmap (port scan) on the provided hostname')
@app_commands.describe(
        domain='Host to run nmap on (syntax: /nmap www.example.com)',
)
async def nmap(message_ctx: discord.Interaction, domain: str, followup: bool=False):
    try:
        channel = message_ctx.channel
        await send_channel_msg(message_ctx, '[I] Port Scanning domain `%s`' % domain, followup=followup)
        await changestatus(message_ctx, "nmap", domain)
        ports_dict = await g_bug_finder.nmap(domain)
        if not len(ports_dict):
            await send_channel_msg(message_ctx, "[I] No ports open on host `%s`" % domain, followup=True)
            return {}

        msg = "[I] Found the following open ports:\n"
        msg += "```"
        for port, p_info in ports_dict.items():
            msg += "\t%s (%s) - %s (%s)\n" % (port, p_info[0], p_info[2], p_info[1])
        msg += "```"
        await changestatus(message_ctx)
        await send_channel_msg(message_ctx, msg, followup=True)
        return ports_dict
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        await changestatus(message_ctx)
        return {}

@client.tree.command(description='Runs Arachni to scan the provided webserver for vulnerabilities.')
@app_commands.describe(
        url='URL to run Arachni on (syntax: /arachni http://www.example.com:80/)',
)
async def arachni(message_ctx: discord.Interaction, url: str, followup: bool=False):
    try:
        channel = message_ctx.channel
        await send_channel_msg(message_ctx, '[I] Running arachni on `%s`' % url, followup=followup)
        await changestatus(message_ctx, "arachni", url)
        arachni_dict = await g_bug_finder.arachni(url)
        if not len(arachni_dict):
            await send_channel_msg(message_ctx, "[I] No vulns found scanning `%s`" % url, followup=True)
            return {}

        msg = "[I] Found %s Vulnerabilities in `%s`\n" % (arachni_dict['issues'], url)
        await changestatus(message_ctx)
        if int(arachni_dict['issues']) > 0 and arachni_dict['report_loc'] is not None:
            msg += "\tGenerated report attached.\n"
            await send_channel_msg(message_ctx, msg, followup=True, file_attach=discord.File(arachni_dict['report_loc']))
        else:
            await send_channel_msg(message_ctx, msg, followup=True)

        return arachni_dict
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        await changestatus(message_ctx)
        return {}

@client.tree.command(description='Grab a random host from the arkadiyt/bounty-targets-data (bug bounty host) repository and attack it.')
async def attackrandom(message_ctx: discord.Interaction, followup: bool=False):
    try:
        channel = message_ctx.channel
        bb_list_url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/wildcards.txt"
        bblu_resp = requests.get(bb_list_url)
        if bblu_resp.status_code == 200:
            bb_audit_lines = bblu_resp.text.splitlines()
            domain = random.choice([dom[2:] for dom in bb_audit_lines if dom.startswith('*.')])
            await send_channel_msg(message_ctx, '[I] Running full attack on random domain `*.%s`' % domain, followup=followup)
            enum_dns = await attack.callback(message_ctx, domain, followup=True)
        return True
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        return False

@client.tree.command(description='Begins a full attack DNSRecon->nmap->dirb->arachni & a sqlmap crawl scan on a provided domain.')
@app_commands.describe(
        domain='Domain to run full attack on (ex: example.com)',
)
async def attack(message_ctx: discord.Interaction, domain: str, followup: bool=False):
    try:
        channel = message_ctx.channel
        await send_channel_msg(message_ctx, '[I] Running full attack on domain `*.%s`' % domain, followup=followup)
        enum_dns = await dns_recon.callback(message_ctx, domain, followup=True)
        for enum_domain,enum_ip in enum_dns.items():
            if enum_domain.endswith(domain):
                enum_ports = await nmap.callback(message_ctx, enum_domain, followup=True)
                for enum_port, enum_p_info in enum_ports.items():
                    enum_p_name = enum_p_info[1]
                    enum_p_type = enum_p_info[0]
                    if enum_p_name in ['http', 'https', 'ssl/http', 'ssl/ssl', 'http-proxy', 'ssl/https-alt']:
                        h_pre = "https" if enum_p_name in ['https', 'ssl/http', 'ssl/ssl', 'ssl/https-alt'] else 'http'
                        enum_url = "%s://%s:%s/" % (h_pre, enum_domain, enum_port)
                        enum_dirs = await dirb.callback(message_ctx, enum_url, followup=True)
                        #for enum_path, enum_pa_info in enum_dirs.items():
                        enum_sqli = await sqlmapcrawl.callback(message_ctx, enum_url, followup=True)
                        enum_wapscan = await arachni.callback(message_ctx, enum_url, followup=True)
        return True
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        return False

@client.tree.command(description='Runs SQLMap and crawls through pages on the provided url')
@app_commands.describe(
        url='URL to run SQLMap crawl on (syntax: /sqlmapcrawl http://www.example.com:80/)',
)
async def sqlmapcrawl(message_ctx: discord.Interaction, url: str, followup: bool=False):
    try:
        channel = message_ctx.channel
        await send_channel_msg(message_ctx, '[I] Running sqlmap w/ crawling on starting url `%s`' % url, followup=followup)
        await changestatus(message_ctx, "sqlmap", url)
        sqli_res_list = await g_bug_finder.sqlmapcrawl(url)
        if not len(sqli_res_list):
            await send_channel_msg(message_ctx, "[I] No SQLis found with sqlmap scanning `%s`" % url, followup=True)
            return []

        msg = "[I] Found SQLinjection vulnerabilities in the following:\n"
        msg += "```"
        for result in sqli_res_list:
            msg += "\t URL: %s\n\t Place: %s\n\t Parameter: %s\n\t Technique: %s\n\t Notes: %s\n" % (result['url'], result['place'], result['param'], result['tech'], result['note']) 
        msg += "```"
        await changestatus(message_ctx)
        await send_channel_msg(message_ctx, msg, followup=True)
        return sqli_res_list
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        await changestatus(message_ctx)
        return []

@client.tree.command(description='Runs dirb which performs a directory brute force attack to find files/directories on the webserver')
@app_commands.describe(
        url='URL to run DirB on (syntax: /dirb http://www.example.com:80/)',
)
async def dirb(message_ctx: discord.Interaction, url: str, followup: bool=False):
    try:
        channel = message_ctx.channel
        await send_channel_msg(message_ctx, '[I] Running dirb on url at `%s`' % url, followup=followup)
        await changestatus(message_ctx, "dirb", url)
        path_dict = await g_bug_finder.dirb(url)
        if not len(path_dict):
            await send_channel_msg(message_ctx, "[I] No files or directories found with dirb scanning `%s`" % url, followup=True)
            return {}

        msg = "[I] Found the following files and directories:\n"
        msg += "```"
        for path, p_info in path_dict.items():
            if p_info[0] == 0 and p_info[1] == 0:
                msg += "\t Path: %s\n" % path
            else:
                msg += "\t Path: %s | Code: %s | Size: %s\n" % (path, p_info[0], p_info[1]) 
        msg += "```"
        await changestatus(message_ctx)
        await send_channel_msg(message_ctx, msg, followup=True)
        return path_dict
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        await changestatus(message_ctx)
        return {}

@client.tree.command(description='This command aborts all currently running jobs.')
async def abort(message_ctx: discord.Interaction, followup:bool=False):
    try:
        channel = message_ctx.channel
        global g_queue, g_channel
        await send_channel_msg(message_ctx, "[I] Aborting all previous jobs and going to sleep.", followup=followup)
        g_queue = asyncio.Queue()
        g_channel = None
        await changestatus(message_ctx)
        if g_task is not None:
            g_task.cancel()
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        return False

@client.event
async def on_ready():
    print('Connected to discord servers.')

@client.event
async def on_message(message):
    pass

class bug_finder:

    def __init__(self):
        pass

    def get_file_buff(self, fileloc):
        try:
            print("[I] Reading file buffer from %s" % fileloc)
            f = open(fileloc)
            buff = f.read()
            f.close()
            return buff
        except Exception as e:
            traceback.print_exc()
            print(e)
            return None

    async def exec_cmd(self, cmd):
        try:
            print("[I] exec_cmd running %s" % cmd)
            p = await asyncio.create_subprocess_shell(cmd, stdin = None, stdout = PIPE, stderr = STDOUT)
            (stdout_log, kp_ret) = await asyncio.gather(self.process_worker(p), self.kill_proc(p))
            #(stdout_log, stderr_log) = await p.communicate()
            #print("[I] exec_cmd output:\n%s" % stdout_log)

            stdout_log = stdout_log.decode('utf-8') if stdout_log is isinstance(stdout_log, (bytes, bytearray)) else stdout_log
            #stderr_log = stderr_log.decode('utf-8') if stderr_log is not None else stderr_log
            return (stdout_log, None)
        except Exception as e:
            print(e)
            print(traceback.format_exc())
            return ('', '')

    async def kill_proc(self, proc):
        try:
            await asyncio.sleep(1)
            proc.kill()
        except ProcessLookupError:
            return
        except Exception as e:
            print(e)
            print(traceback.format_exc())

    async def process_worker(self, proc):
        try:
            stdout = []
            while True:
                line = await proc.stdout.readline()
                if line == b'':
                    break
                elif isinstance(line, list):
                    stdout.append(''.join(line).decode('utf-8'))
                    sys.stdout.write(''.join(line).decode('utf-8'))
                else:
                    sys.stdout.write(line.decode('utf-8'))
                    stdout.append(line.decode('utf-8'))
                #sys.stdout.flush()
                #print(''.join(stdout))
            await proc.wait()
            return ''.join(stdout)
        except Exception as e:
                print(e)
                print(traceback.format_exc())
                return ""

    async def arachni(self, target):
        num_issues = 0
        report_loc = None
        ret = {}
        domain = urlparse(target).hostname
        report_save_path = '/tmp/%s.afr' % domain
        (stdout_log, stderr_log) = await self.exec_cmd("%s --http-user-agent 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.117 Safari/537.36' --timeout=04:00:00 --http-request-queue-size=50 --http-request-concurrency=2 --browser-cluster-pool-size=2 --output-only-positives --audit-links --audit-forms --audit-cookies --report-save-path='%s' --checks=active/*,-csrf '%s'" % (ARACHNI_LOC, shlex.quote(report_save_path), shlex.quote(target)))
        if stdout_log is None and stderr_log is None:
            return ret
        for line in stdout_log.split('\n'):
            if line.startswith('[-] '):
                issues_re = r"\[-\] With issues: ([0-9]+) \( [0-9]+% \)"
                issues_rem = re.search(issues_re, line)
                if issues_rem:
                    num_issues = issues_rem.group(1)
                    if int(num_issues) > 0:
                        print("[I] %s issues found." % num_issues)
                        output = "/tmp/%s.zip" % domain
                        if await self.arachni_reporter(report_save_path, output):
                            print("[I] - Report generated at %s" % output)
                            report_loc = output
        ret['issues'] = num_issues
        ret['report_loc'] = report_loc
        return ret

    async def arachni_reporter(self, report, output):
        (stdout_log, stderr_log) = await self.exec_cmd("%s '%s' --reporter=html:outfile='%s'" % (ARACHNI_REPORTER_LOC, report, output))
        if stdout_log is None and stderr_log is None:
            return False
        for line in stdout_log.split('\n'):
            if line.startswith('[*] HTML: Saved in '):
                return True
        return False

    async def dirb(self, url):
        found = {}
        (stdout_log, stderr_log) = await self.exec_cmd("%s '%s' /usr/share/dirb/wordlists/common.txt -S -r" % (DIRB_LOC, shlex.quote(url)))
        if stdout_log is None and stderr_log is None:
            return {}
        for line in stdout_log.split('\n'):
            fpage_re = r"\+ ([^ ]+) \(CODE:([0-9]+)\|SIZE:([0-9]+)\)"
            fpage_rem = re.search(fpage_re, line)
            if fpage_rem:
                fp_url = fpage_rem.group(1)
                fp_code = fpage_rem.group(2)
                fp_size = fpage_rem.group(3)
                found[fp_url] = [fp_code, fp_size]
                continue

            dir_re = r"==> DIRECTORY: (.*)"
            dir_rem = re.search(dir_re, line)
            if dir_rem:
                fp_url = dir_rem.group(1)
                fp_code = 0
                fp_size = 0
                found[fp_url] = [fp_code, fp_size]
        return found

    async def nmap(self, domain):
        open_ports = {}
        (stdout_log, stderr_log) = await self.exec_cmd("sudo %s -sV -Pn -T3 '%s'" % (NMAP_LOC, shlex.quote(domain)))
        if stdout_log is None and stderr_log is None:
            return {}
        for line in stdout_log.split('\n'):
            port_re = r"([0-9]+)\/([^ ]+)[ ]+open[ ]+([^ ]+)[ ]+(.*)"
            p_rem = re.search(port_re, line)
            if p_rem:
                port = p_rem.group(1)
                p_type = p_rem.group(2)
                p_name = p_rem.group(3)
                p_ver = p_rem.group(4)
                open_ports[port] = [p_type, p_name, p_ver]
        return open_ports

    async def sqlmapcrawl(self, target):
        sqlmap_results = []
        sqlmap_cmd = "python3 %s -u '%s' --forms --batch --crawl=3 --threads=1 --tamper='between,randomcase,space2comment' -v 3 --level=1 --random-agent -o --smart --current-user" % (SQLMAP_LOC, shlex.quote(target))
        (stdout_log, stderr_log) = await self.exec_cmd(sqlmap_cmd)
        if stdout_log is None and stderr_log is None:
            return {}
        for line in stdout_log.split('\n'):
            sqlmap_out_re = r"you can find results of scanning in multiple targets mode inside the CSV file '([^']+)'"
            sqlmap_out_rem = re.search(sqlmap_out_re, line)
            if sqlmap_out_rem:
                sqlmap_out = sqlmap_out_rem.group(1)
                if sqlmap_out:
                    #print("[I] SQLMap CSV report saved to %s." % sqlmap_out)
                    sqlmap_results = await self.sqlmap_parse(sqlmap_out)
                    #print("[I] Found %s SQLinjection vulnerabilities." % len(sqlmap_results))
                    #for result in sqlmap_results:
                        #print("URL: %s\nPlace: %s\nParam: %s\nTechnique: %s\nNotes: %s\n" % (result['url'], result['place'], result['param'], result['tech'], result['note']))
        return sqlmap_results

    async def sqlmap_parse(self, sqlmap_csv_file):
        ret_list = []
        sqlmap_csv = self.get_file_buff(sqlmap_csv_file)
        for idx,line in enumerate(sqlmap_csv.split('\n')):
            if idx != 0:
                csv_vals = line.split(',')
                if len(csv_vals) == 5 :
                    s = {}
                    s['url'] = csv_vals[0] 
                    s['place']= csv_vals[1]
                    s['param'] = csv_vals[2]
                    s['tech'] = csv_vals[3]
                    s['note'] = csv_vals[4]
                    ret_list.append(s)
        return ret_list

    async def dns_recon(self, domain):
        domains = {}
        #dnsrecon_cmd = "python3 /usr/local/src/dnsrecon/dnsrecon.py -t std,brt -D /usr/local/src/subdomain-dictionary.txt -d %s -n 8.8.8.8 -b -y -k -c ~/.config/%s.domains.csv" % (shlex.quote(domain), shlex.quote(domain))
        csv_loc = "%s/.config/%s.domains.csv" % (expanduser("~"), shlex.quote(domain))
        dnsrecon_cmd = "python3 %s -t std,brt,axfr -D /usr/local/src/subdomain-dictionary.txt -d '%s' -n 8.8.8.8 -c '%s' " % (DNSRECON_LOC, shlex.quote(domain), csv_loc)
        (stdout_log, stderr_log) = await self.exec_cmd(dnsrecon_cmd)

        if not stdout_log and not stderr_log:
            return {}

        if 'Saving records to CSV file' not in stdout_log:
            print("[E] Could not determine CSV file location.")
            return domains

        dnsrecon_csv = self.get_file_buff(csv_loc)
        for idx,line in enumerate(dnsrecon_csv.split('\n')):
            if idx != 0:
                csv_vals = line.split(',')
                if len(csv_vals) >= 3 :
                    d_type = csv_vals[0] 
                    d_name = csv_vals[1]
                    d_val = csv_vals[2]
                    if d_type == 'A':
                        domains[d_name] = d_val

        return domains

    def attack(self, domain):
        nmap_ret = self.nmap(domain)
        for port,pinfo in nmap_ret.items():
            port_type = pinfo[0]
            port_name = pinfo[1]

            if port_name in ['http', 'https']:
                print('%s://%s:%s/' % (port_name, domain, port))


g_queue = asyncio.Queue()
g_bug_finder = bug_finder()
g_channel = None
g_task = None

client.run(TOKEN)
