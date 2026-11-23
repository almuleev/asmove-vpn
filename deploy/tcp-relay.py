"""Restricted TCP forwarding to the current EU node; VLESS/REALITY remains end to end."""
import argparse
import asyncio
import ipaddress
import json
import math
from pathlib import Path
import time


def read_config(path):
    value = json.loads(Path(path).read_text())
    expiry = value.get('expires_at', 0)
    if (not value.get('enabled') or type(value.get('port')) is not int
            or not 1024 <= value['port'] <= 65535
            or (expiry is not None and (type(expiry) not in (int, float)
                or not math.isfinite(expiry) or expiry <= time.time()))):
        raise ValueError('inactive relay')
    for address in value['allowed_peers']:
        ipaddress.IPv4Address(address)
    return value


def destination(path, identifier):
    value = json.loads(Path(path).read_text())
    node = next(node for node in value['nodes'] if node['id'] == identifier)
    address = ipaddress.IPv4Address(node['ip'])
    if not address.is_global or node.get('country') == 'ru':
        raise ValueError('invalid relay destination')
    return str(address), 443


async def serve(config_path, infrastructure_path):
    config = read_config(config_path)
    active = 0

    async def handle(reader, writer):
        nonlocal active
        upstream = None
        admitted = False
        try:
            current = read_config(config_path)
            peer = writer.get_extra_info('peername')[0]
            if peer not in current['allowed_peers'] or active >= 40:
                return
            active += 1; admitted = True
            address, port = destination(infrastructure_path, current['target_node'])
            remote_reader, upstream = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=8)

            async def copy(source, target):
                while True:
                    data = await asyncio.wait_for(source.read(65536), timeout=180)
                    if not data:
                        return
                    target.write(data)
                    await asyncio.wait_for(target.drain(), timeout=30)

            tasks = [asyncio.create_task(copy(reader, upstream)), asyncio.create_task(copy(remote_reader, writer))]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, ValueError, KeyError, StopIteration, asyncio.TimeoutError):
            pass
        finally:
            if admitted:
                active -= 1
            for stream in (upstream, writer):
                if stream:
                    stream.close()
                    try:
                        await asyncio.wait_for(stream.wait_closed(), timeout=2)
                    except (OSError, asyncio.TimeoutError):
                        pass

    server = await asyncio.start_server(handle, '0.0.0.0', config['port'])
    async with server:
        if config['expires_at'] is None:
            await server.serve_forever()
        else:
            await asyncio.sleep(max(0, config['expires_at'] - time.time()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--infrastructure', required=True)
    args = parser.parse_args()
    asyncio.run(serve(args.config, args.infrastructure))


if __name__ == '__main__':
    main()
