#!/usr/bin/env python3
"""Attest or verify a strictly QA-only signed KDE Connect candidate, never publish.

The expected certificate fingerprint MUST come from independently trusted key
records for device acceptance; hosted CI can additionally compare it to the
preconfigured repository signing-secret value before creating the artifact.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

QA_CODES = tuple(range(13704, 13709))
QA_PACKAGE = 'org.kde.kdeconnect_tp.mikey'
QA_VERSION = '1.37.3-community-qa'
QA_NAME = 'kdeconnect-community.apk'
MAX_SIZE = 250 * 1024 * 1024
SHA40 = re.compile(r'[a-f0-9]{40}\Z')
SHA64 = re.compile(r'[a-fA-F0-9]{64}\Z')

class Rejected(ValueError):
    pass

def must(condition: bool, detail: str) -> None:
    if not condition:
        raise Rejected(detail)

def inspect_tool(tool: str, args: list[str]) -> str:
    """Use an installed SDK build-tool and retain both apksigner output streams.

    A zero exit code from the actual apksigner verifier is mandatory. No path
    ever substitutes keytool, APK manifest metadata, or a plain unzip check.
    """
    from shutil import which
    path = None
    sdk = os.getenv('ANDROID_HOME') or os.getenv('ANDROID_SDK_ROOT')
    if sdk:
        root = Path(sdk, 'build-tools')
        candidates = [p for p in root.glob('*/'+tool) if p.is_file()]
        def version_key(p: Path) -> tuple[int, ...]:
            parts = re.findall(r'\d+', p.parent.name)
            return tuple(map(int, parts)) if parts else (0,)
        if candidates:
            path = str(max(candidates, key=version_key))
    if path is None:
        path = which(tool)
    must(bool(path), f'{tool} unavailable')
    try:
        cp = subprocess.run([path, *args], capture_output=True, text=True,
                            timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Rejected(f'{tool} execution failed: {type(exc).__name__}') from exc
    if tool == 'apksigner':
        # Android build-tools and wrapper versions may choose different streams.
        combined = (cp.stdout or '') + '\n' + (cp.stderr or '')
        must(cp.returncode == 0,
             f'apksigner verification failed (exit={cp.returncode}); '
             f'apksigner_report_shape={report_shape(combined)}')
        return combined
    must(cp.returncode == 0, f'{tool} failed (exit={cp.returncode})')
    return cp.stdout

def apk_hash(apk: Path) -> str:
    h=hashlib.sha256()
    with apk.open('rb') as f:
        for chunk in iter(lambda: f.read(65536),b''):
            h.update(chunk)
    return h.hexdigest()

# Android build-tools may label a signer by index or by supported SDK range.
# Accept only a verified single signing identity, never manifest/keytool output.
SIGNER_SHA256_ROW = re.compile(
    r'^Signer\s+(?P<label>.+?)\s+certificate SHA-256 digest:\s*'
    r'(?P<digest>\S(?:.*\S)?)\s*$', re.MULTILINE)
SIGNER_SDK_RANGE = re.compile(
    r'^\(minSdkVersion=\d+(?:,\s*maxSdkVersion=\d+)?\)$')
SIGNER_NUMBER = re.compile(
    r'^#(?P<index>[1-9]\d*)(?:\s+(?P<sdk>\(minSdkVersion=\d+'
    r'(?:,\s*maxSdkVersion=\d+)?\)))?$')
# Android build-tools 37+ can report active scheme signers as
# 'V3.0 Signer: certificate SHA-256 digest: ...' instead of 'Signer #1 ...'.
# Accept only these explicit scheme labels, never arbitrary certificate text.
SCHEME_SIGNER_SHA256_ROW = re.compile(
    r'^V(?P<scheme>2(?:\.0)?|3\.0|3\.1|3\.2) Signer:'
    r'(?: (?P<sdk>\(minSdkVersion=\d+(?:,\s*maxSdkVersion=\d+)?\)))?'
    r' certificate SHA-256 digest:\s*(?P<digest>\S(?:.*\S)?)\s*$')
SIGNER_COUNT = re.compile(r'^Number of signers:\s*(\S+)\s*$', re.MULTILINE)
HEX_COLON_SHA256 = re.compile(r'^(?:[a-fA-F0-9]{2}:){31}[a-fA-F0-9]{2}$')
PEM_CERTIFICATE = re.compile(
    r'(?m)^-----BEGIN CERTIFICATE-----\r?\n'
    r'(?:[A-Za-z0-9+/=]+\r?\n)+'
    r'-----END CERTIFICATE-----(?:\r?\n|$)')


def report_shape(report: str) -> str:
    """Bounded diagnostics that cannot expose cert bytes, DN or PEM data."""
    lines=report.splitlines()
    candidates=[line for line in lines if 'certificate SHA-256' in line
                and (line.startswith('Signer ') or
                     re.match(r'^V[0-9.]+ Signer', line))]
    kinds=[];widths=[]
    for line in candidates[:12]:
        legacy=SIGNER_SHA256_ROW.fullmatch(line)
        scheme=SCHEME_SIGNER_SHA256_ROW.fullmatch(line) if legacy is None else None
        if legacy is None and scheme is None:
            kinds.append('unparsed');widths.append(0)
        elif legacy is not None:
            label=legacy.group('label')
            kinds.append('numbered' if label.startswith('#') else
                         'sdk-range' if label.startswith('(') else 'other')
            widths.append(min(len(legacy.group('digest')),256))
        else:
            kinds.append('scheme-v'+scheme.group('scheme'))
            widths.append(min(len(scheme.group('digest')),256))
    return ('lines='+str(min(len(lines),9999))+
            ' sha256_rows='+str(len(candidates))+
            ' label_kinds='+','.join(kinds)+
            ' digest_widths='+','.join(map(str,widths))+
            ' pem_blocks='+str(report.count('-----BEGIN CERTIFICATE-----')))


def require_single_signer(report: str) -> None:
    counts=SIGNER_COUNT.findall(report)
    must(all(x=='1' for x in counts), 'Multiple APK signers detected')
    for line in report.splitlines():
        n=re.match(r'^Signer #([0-9]+)(?:\s|$)', line)
        if n is not None:
            must(n.group(1)=='1', 'Multiple APK signers detected')


def parse_verified_signer_report(report: str) -> str:
    """Parse only recognized signer rows from successful apksigner verify."""
    require_single_signer(report)
    candidates=[line for line in report.splitlines()
                if 'certificate SHA-256' in line and
                (line.startswith('Signer ') or re.match(r'^V[0-9.]+ Signer', line))]
    must(bool(candidates), 'Missing apksigner SHA-256 certificate output')
    digests=[]
    seen_labels=set()
    for line in candidates:
        row=SIGNER_SHA256_ROW.fullmatch(line)
        if row is not None:
            label=row.group('label')
            match=SIGNER_NUMBER.fullmatch(label)
            if match is not None:
                must(int(match.group('index'))==1, 'Multiple APK signers detected')
            else:
                must(SIGNER_SDK_RANGE.fullmatch(label) is not None,
                     'Unrecognized apksigner signer label')
            identity='legacy:'+label
        else:
            row=SCHEME_SIGNER_SHA256_ROW.fullmatch(line)
            must(row is not None, 'Unrecognized apksigner SHA-256 signer row')
            sdk=row.group('sdk')
            must(sdk is None or SIGNER_SDK_RANGE.fullmatch(sdk) is not None,
                 'Invalid apksigner scheme SDK range')
            identity='v'+row.group('scheme')+':'+(sdk or '')
        must(identity not in seen_labels, 'Duplicate APK signer certificate row')
        seen_labels.add(identity)
        digest=row.group('digest')
        if HEX_COLON_SHA256.fullmatch(digest):
            digest=digest.replace(':','')
        must(SHA64.fullmatch(digest) is not None,
             'Invalid apksigner SHA-256 certificate digest')
        digests.append(digest.lower())
    must(len(set(digests))==1,
         'Multiple distinct signing certificates detected across APK SDK ranges')
    return digests[0]

def parse_verified_pem_report(report: str) -> str:
    """Hash the sole verified apksigner PEM, not an unverified APK entry."""
    import ssl
    require_single_signer(report)
    certs=PEM_CERTIFICATE.findall(report)
    must(len(certs)==1 and report.count('-----BEGIN CERTIFICATE-----')==1 and
         report.count('-----END CERTIFICATE-----')==1,
         'Expected exactly one apksigner signing certificate PEM')
    try:
        der=ssl.PEM_cert_to_DER_cert(certs[0])
    except (ValueError, TypeError) as exc:
        raise Rejected('Invalid verified signing certificate PEM') from exc
    must(16 <= len(der) <= 16384 and der[0]==0x30,
         'Invalid verified signing certificate encoding')
    return hashlib.sha256(der).hexdigest()


def inspected_signer(apk: Path) -> str:
    report=inspect_tool('apksigner', [
        'verify','--min-sdk-version','24','--verbose','--print-certs',str(apk)])
    try:
        return parse_verified_signer_report(report)
    except Rejected as exc:
        # Do not hide malformed digest rows, invalid labels or extra signers.
        # The PEM path is allowed only when no digest information is present.
        if 'certificate SHA-256' in report or 'Multiple APK signers' in str(exc):
            raise Rejected(f'{exc}; apksigner_report_shape={report_shape(report)}') from exc
        require_single_signer(report)
        pem_report=inspect_tool('apksigner', [
            'verify','--min-sdk-version','24','--verbose','--print-certs-pem',str(apk)])
        try:
            return parse_verified_pem_report(pem_report)
        except Rejected as pem_exc:
            raise Rejected('Verified apksigner PEM fallback refused: '
                           +str(pem_exc)+'; apksigner_report_shape='
                           +report_shape(pem_report)) from pem_exc

def inspected_identity(apk: Path) -> tuple[str,int,str]:
    report=inspect_tool('aapt',['dump','badging',str(apk)])
    row=next((s for s in report.splitlines() if s.startswith('package: ')),'')
    info=dict(re.findall(r"(name|versionCode|versionName)='([^']*)'",row))
    must(set(info)=={'name','versionCode','versionName'},'Bad APK badging')
    try:
        code=int(info['versionCode'])
    except ValueError as e:
        raise Rejected('Invalid APK versionCode') from e
    return info['name'],code,info['versionName']

def verify(apk: Path, meta: dict[str,Any] | None, cert: str, source: str, code: int) -> dict[str,Any]:
    must(bool(SHA40.fullmatch(source)), 'Source SHA must be exact SHA-1')
    must(bool(SHA64.fullmatch(cert)), 'Trusted certificate fingerprint required')
    must(code in QA_CODES, 'Not a reserved QA version code')
    must(not apk.is_symlink() and apk.is_file() and apk.name==QA_NAME,'Unexpected or symlinked APK')
    size=apk.stat().st_size
    must(1024 <= size <= MAX_SIZE,'Invalid QA APK size')
    digest=apk_hash(apk)
    signer=inspected_signer(apk)
    must(signer == cert.lower(), 'APK signer does not match independent trust pin')
    package,ver,vername=inspected_identity(apk)
    must((package,ver,vername)==(QA_PACKAGE,code,QA_VERSION),'Wrong QA APK package/version/name')
    expected={
        'schema':'kdeconnect.signed-qa.v1',
        'qualification_only':True,
        'publishable_release':False,
        'source_commit':source,
        'qa_tag':f'kde-qa-{source}',
        'apk_name':QA_NAME,
        'apk_size':size,
        'apk_sha256':digest,
        'package_name':QA_PACKAGE,
        'version_code':code,
        'version_name':vername,
        'signing_certificate_sha256':signer,
    }
    if meta is not None:
        must(meta==expected,'QA metadata differs from signed APK or trusted source')
    return expected

def main(argv: list[str] | None=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['attest','verify'])
    p.add_argument('--apk',type=Path,required=True)
    p.add_argument('--metadata',type=Path,required=True)
    p.add_argument('--expected-cert',required=True)
    p.add_argument('--expected-source',required=True)
    p.add_argument('--expected-code',required=True,type=int)
    args=p.parse_args(argv)
    try:
        if args.mode=='verify':
            must(args.metadata.is_file() and not args.metadata.is_symlink() and
                 args.metadata.stat().st_size < 16384,'Invalid QA metadata')
            meta=json.loads(args.metadata.read_text(encoding='utf8'))
            must(isinstance(meta,dict),'QA metadata is not an object')
        else:
            must(not args.metadata.exists() and not args.metadata.is_symlink(), 'Refusing metadata overwrite')
            meta=None
        expected=verify(args.apk,meta,args.expected_cert,args.expected_source,args.expected_code)
        if args.mode=='attest':
            args.metadata.write_text(json.dumps(expected,indent=2,sort_keys=True)+'\n',encoding='utf8')
        print('KDE_SIGNED_QA_VERIFIED_ONLY code='+str(args.expected_code)+
              ' signer_sha256='+expected['signing_certificate_sha256']+
              ' apk_sha256='+expected['apk_sha256'])
        return 0
    except (Rejected, OSError, ValueError) as e:
        print('KDE_SIGNED_QA_REFUSED '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
