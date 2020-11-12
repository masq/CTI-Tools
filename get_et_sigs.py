#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Retrieves and unpacks the latest ET sigs.

    :author: Spencer Walden
    :date: 2020-11-06
"""

# Standard imports
import argparse
import sys
import pathlib
import io
from typing import Any, Dict

# Third party imports
import requests
import tarfile

IDS_VERSION='5.0.0'
OINKCODE=''
GET_SNORT=False
ET_URLF = (
    'https://'
    'rules.emergingthreats.net'
    '/{oinkcode}/{ids}-{version}/'
    '{ruleset}.rules.tar.gz'
)
RST = '\033[0m'
BLU = '\033[96m'
GRN = '\033[92m'
RED = '\033[91m'
YLW = '\033[93m'


def main(
        download_to: str = '.',
        version: str = IDS_VERSION,
        get_snort: bool = GET_SNORT,
        oinkcode: str = OINKCODE
    ):
    """
        Performs downloading and uncompressing of ET(PRO|OPEN) rules as
        specified to the given directory
    """

    should_get_pro = len(oinkcode) > 0
    ruleset_suffix = 'PRO' if should_get_pro else 'OPEN'
    # print('oinkcode:', type(oinkcode), oinkcode)  # debug
    print(f'{BLU}[*]{RST} Getting "ET{ruleset_suffix}" rules...', file=sys.stderr)
    response = requests.get(
        url=ET_URLF.format(
            oinkcode=oinkcode if should_get_pro else 'open',
            ids='snort' if get_snort else 'suricata',
            version=version,
            ruleset='etpro' if should_get_pro else 'emerging' 
        )
    )

    response.raise_for_status()
    print(f'{GRN}[+]{RST} Got "ET{ruleset_suffix}" rules!', file=sys.stderr)

    download_dir = pathlib.Path(download_to).expanduser().absolute()
    tarball = tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz')
    dirname, *_ = tarball.getnames()  # Should really only return 1 name, "rules"
    print(f'{BLU}[*]{RST} Extracting rules to "{download_dir / dirname}"...', file=sys.stderr)

    tarball.extractall(download_dir)
    tarball.close()
    print(f'{GRN}[+]{RST} Rules successfully extracted!', file=sys.stderr)



def cli() -> Dict[str, Any]:
    """
        Parse command line arguments
    """

    argp = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    argp.add_argument(
        '-o',
        '--output',
        help='Directory to download to',
        metavar='/path/to/download/directory',
        default='.'
    )

    argp.add_argument(
        '-k'
        '--oinkcode',
        dest='oinkcode',
        help='Your ETPRO oinkcode',
        metavar=1605143374,
        default=''
    )

    argp.add_argument(
        '--snort',
        help=(
            'A flag to say to use the Snort versions of the ruleset '
            '(as opposed to the suricata versions)'
        ),
        action='store_true',
        default=False
    )

    argp.add_argument(
        '--version',
        help='The version of the ruleset you want to download',
        default=IDS_VERSION,
        metavar=IDS_VERSION
    )

    args = argp.parse_args()
    return {
        'download_to': args.output,
        'version': args.version,
        'get_snort': args.snort,
        'oinkcode': args.oinkcode
    }


if __name__ == '__main__':
    main(**cli())
