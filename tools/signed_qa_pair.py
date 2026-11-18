#!/usr/bin/env python3
"""Verify every QA-only signed APK and strict monotonic same-signer upgrade chain."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import signed_qa as qa


def inspect_chain(root:Path,source:str) -> dict:
    qa.must(qa.SHA40.fullmatch(source) is not None,'Exact source SHA required')
    qa.must(root.is_dir() and not root.is_symlink(),'Missing QA artifact directory')
    expected_names={f'kdeconnect-signed-qa-{source}-{code}' for code in qa.QA_CODES}
    actual={p.name for p in root.iterdir()}
    # gh run download without an artifact name also includes the chain summary.
    optional_summary=f'kdeconnect-signed-qa-chain-{source}'
    qa.must(actual in (expected_names,expected_names|{optional_summary}),
            'Expected exactly five QA candidates plus optional chain summary')
    cert=None
    items=[]
    for code in qa.QA_CODES:
        path=root/f'kdeconnect-signed-qa-{source}-{code}'
        qa.must(not path.is_symlink() and path.is_dir(),'Invalid QA artifact directory')
        qa.must({p.name for p in path.iterdir()}=={'kdeconnect-community.apk','qa.json'},'Unexpected QA artifact files')
        meta_path=path/'qa.json'
        qa.must(not meta_path.is_symlink() and meta_path.stat().st_size<16384,'Invalid QA metadata')
        meta=json.loads(meta_path.read_text(encoding='utf-8'))
        qa.must(isinstance(meta,dict),'Invalid metadata structure')
        if cert is None:
            cert=meta.get('signing_certificate_sha256')
            qa.must(isinstance(cert,str) and qa.SHA64.fullmatch(cert) is not None,'Missing certificate pin')
        found=qa.verify(path/'kdeconnect-community.apk',meta,cert,source,code)
        items.append({'version_code':code,'apk_sha256':found['apk_sha256']})
    return {'schema':'kdeconnect.signed-qa-chain.v1','status':'SIGNED_QA_ONLY','qualification_only':True,
            'source_commit':source,'signing_certificate_sha256':cert,'candidates':items,
            'production_release_qualified':False,'device_qualified':False,
            'independent_offline_trust_required':True}


def main(argv: list[str] | None=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory',required=True,type=Path)
    p.add_argument('--expected-source',required=True)
    p.add_argument('--receipt',required=True,type=Path)
    p.add_argument('--expected-cert',help='Independently trusted fingerprint for local verification')
    args=p.parse_args(argv)
    try:
        found=inspect_chain(args.directory,args.expected_source)
        if args.expected_cert:
            qa.must(qa.SHA64.fullmatch(args.expected_cert) is not None and
                    args.expected_cert.lower()==found['signing_certificate_sha256'],
                    'QA chain does not match independent signing identity')
            found['independent_offline_trust_required']=False
            found['independent_signer_matched']=True
        qa.must(not args.receipt.exists() and not args.receipt.is_symlink(),'Refusing receipt overwrite')
        args.receipt.write_text(json.dumps(found,indent=2,sort_keys=True)+'\n',encoding='utf-8')
        print('KDE_SIGNED_QA_CHAIN_PASS codes=13704..13708 source='+args.expected_source)
        return 0
    except (qa.Rejected, OSError, ValueError) as e:
        print('KDE_SIGNED_QA_CHAIN_REFUSED '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
