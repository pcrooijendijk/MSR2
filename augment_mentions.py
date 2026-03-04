import argparse
import csv
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Pattern, Set, Tuple

from github import Github, Auth
from github.PullRequest import PullRequest
from github.Repository import Repository
from github.GithubException import IncompletableObject
from dotenv import load_dotenv

load_dotenv() 
KEYS = [os.getenv(f"KEY_{i}") for i in range(11) if os.getenv(f"KEY_{i}")]

PATTERNS: Dict[str, Pattern[str]] = {
    "CVE": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "RUSTSEC": re.compile(r"\bRUSTSEC-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "PYSEC": re.compile(r"\bPYSEC-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "MAL": re.compile(r"\bMAL-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "OSV": re.compile(r"\bOSV-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "GSD": re.compile(r"\bGSD-\d{4}-\d{4,7}\b", re.IGNORECASE),

    "GHSA": re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE),
    "GO": re.compile(r"\bGO-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "ASB": re.compile(r"\b(?:ASB|PUB)-A-\d{4}-\d{2}-\d{2}\b", re.IGNORECASE),

    "RHSA": re.compile(r"\bRH[SBA]-\d{4}:\d+\b", re.IGNORECASE),
    "ALSA": re.compile(r"\bAL[SBE]A-\d{4}:\d+\b", re.IGNORECASE),
    "RLSA": re.compile(r"\bR[LX]SA-\d{4}:\d+\b", re.IGNORECASE),

    "DEBIAN": re.compile(r"\b(?:DSA|DLA|DTSA)-\d{4,5}-\d{1,2}\b", re.IGNORECASE),
    "ALPINE": re.compile(r"\bALPINE-CVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "CURL": re.compile(r"\bCURL-CVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "MAGEIA": re.compile(r"\bMGASA-\d{4}-\d{3,5}\b", re.IGNORECASE),
    "SUSE": re.compile(r"\b(?:openSUSE|SUSE)-[A-Z]{2}-\d{4}:\d+\b", re.IGNORECASE),
    "UBUNTU": re.compile(r"\bUSN-\d{4}-\d{1,2}\b", re.IGNORECASE),

    "CWE": re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE),

    "ALPAQUITA": re.compile(r"\bBELL-CVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "BITNAMI": re.compile(r"\bBIT-kibana-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "CHAINGUARD": re.compile(r"\bCGA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE),
    "CRAN": re.compile(r"\b[HR]SEC-\d{4}-\d{1,2}\b", re.IGNORECASE),
    "ECHO": re.compile(r"\bECHO-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE),
    "JULIA": re.compile(r"\bJLSEC-\d{4}-\d{2,4}\b", re.IGNORECASE),
    "MINIMOS": re.compile(r"\bMINI-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE),
    "OPENEULER": re.compile(r"\bOESA-\d{4}-\d{4}\b", re.IGNORECASE),

    "denial_of_service": re.compile(r"(?i)(denial.of.service|dos|infinite.loop|ReDoS)", re.IGNORECASE),
    "remote_code_execution": re.compile(r"(?i)(remote.code.execution|RCE|exploit|malicious)", re.IGNORECASE),
    "web_vulnerabilities_1": re.compile(r"(?i)(session.fixation|hijack|x−frame−options|\bcross−oriдin\b|unauthori[z|s]ed)", re.IGNORECASE),
    "web_vulnerabilities_2": re.compile(r"(?i)(\bXSS\b|cross.site|XXE|open.redirect|clickjack|session.fixation|hijack|x−frame−options|\bcross−oriдin\b|unauthori[z|s]ed)", re.IGNORECASE),
    "vulnerability_ids_1": re.compile(r"(?i)(CVE|CWE|NVD|vuln|advisory)", re.IGNORECASE),
    "vulnerability_ids_2": re.compile(r"(?i)(insecure|security|OSVDB)", re.IGNORECASE),
    "directory_traversal": re.compile(r"(?i)(directory.traversal)", re.IGNORECASE),
    # "strong_vuln_patterns": re.compile(r"(?i)(denial.of.service|\bXXE\b|remote.code.execution|\bopen.redirect|OSVDB|\bvuln|\bCVE\b|\bXSS\b|\bReDoS\b|\bNVD\b|malicious|x− frame− options|attack|cross.site|exploit|directory.traversal|\bRCE\b|\bdos\b|\bXSRF\b|clickjack|session.fixation|hijack|advisory|insecure|security|\bcross− oriдin\b|unauthori[z|s]ed|infinite.loop)", re.IGNORECASE),
    
    "url": re.compile(
    r"^https:\/\/(?:"
    r"storage\.googleapis\.com\/android-osv\/|"
    r"errata\.almalinux\.org\/|"
    r"security\.alpinelinux\.org\/vuln\/|"
    r"bell-sw\.com\/vulnerability-report\/|"
    r"github\.com\/bitnami\/vulndb\/blob\/main\/data\/|"
    r"github\.com\/cleanstart-dev\/cleanstart-security-advisories\/?|"
    r"curl\.se\/docs\/|"
    r"nvd\.nist\.gov\/vuln\/detail\/|"
    r"security-tracker\.debian\.org\/tracker\/|"
    r"github\.com\/docker-hardened-images\/advisories\/?|"
    r"www\.drupal\.org\/security\/|"
    r"debian\.org\/security\/|"
    r"github\.com\/erlef-cna\/website\/tree\/main\/_data\/osv\/|"
    r"deb\.freexian\.com\/extended-lts\/tracker\/|"
    r"github\.com\/advisories\/|"
    r"pkg\.go\.dev\/vuln\/|"
    r"gsd\.id\/|"
    r"github\.com\/JuliaLang\/SecurityAdvisories\.jl\/blob\/main\/advisories\/published\/|"
    r"kubernetes\.io\/docs\/reference\/issues-security\/official-cve-feed\/index\.json|"
    r"ubuntu\.com\/security\/notices\/|"
    r"advisories\.mageia\.org\/|"
    r"www\.openeuler\.org\/en\/security\/security-bulletins\/detail\/\?id=openEuler-SA-|"
    r"github\.com\/ocaml\/security-advisories\/advisories\/|"
    r"osv\.dev\/vulnerability\/|"
    r"github\.com\/vmware\/photon\/wiki\/|"
    r"access\.redhat\.com\/security\/security-updates\/security-advisories|"
    r"errata\.rockylinux\.org\/|"
    r"rustsec\.org\/advisories\/|"
    r"www\.suse\.com\/support\/update\/|"
    r"ubuntu\.com\/security\/|"
    r"github\.com\/google\/chromium-policy-vulnfeed\/blob\/main\/advisories\/V8-advisory\.json"
    r")"
)}

@dataclass(frozen=True)
class Match:
    pattern_name: str
    pr_number: int
    pr_url: str
    where: str
    match_text: str
    snippet: str
    actor_login: str
    actor_type: str
    mentioned_at: str

with open("urls.json", "r") as f: 
    additional_urls = json.load(f)

def extract_search_tokens(pattern_name: str, regex: Pattern[str]) -> str:
    # Returning the Github search string
    if pattern_name == "SUSE":
        return '"openSUSE" SUSE'
    if pattern_name == "ASB":
        return "ASB PUB"
    if pattern_name == "denial_of_service":
        return "denial of service OR DOS OR infinite lop OR ReDoS"
    if pattern_name == "remote_code_execution":
        return "Remote code execution OR RCE OR exploit OR malicious"
    if pattern_name == "web_vulnerabilities_1":
        return "XSS OR cross site OR XXE OR open redirect OR clickjack"
    if pattern_name == "web_vulnerabilities_2":
        return "session fixation OR hijack OR x-frame-options OR cross−oriдin OR unauthorised"
    if pattern_name == "vulnerability_ids_1":
        return "CVE OR CWE OR NVD OR vuln OR advisory"
    if pattern_name == "vulnerability_ids_2":
        return "insecure OR security OR OSVDB"
    if pattern_name == "directory_traversal":
        return "directory traversal"
    # if pattern_name == "url":
    #     return " OR ".join(additional_urls)
    return pattern_name

def search_candidate_prs(
    gh: Github,
    repo_full_name: str,
    token_query: str,
    state: str,
    max_results: int,
    sleep_s: float,
) -> List[PullRequest]:
    qualifiers = []
    if state == "open":
        qualifiers.append("is:open")
    elif state == "closed":
        qualifiers.append("is:closed")
    elif state == "merged":
        qualifiers.append("is:merged")

    q = f'repo:{repo_full_name} type:pr updated:>2025-01-01 {" ".join(qualifiers)} {token_query}'.strip()

    prs: List[PullRequest] = []
    results = gh.search_issues(q)
    for i, issue in enumerate(results):
        if i >= max_results:
            break
        prs.append(issue.as_pull_request())
        if sleep_s:
            time.sleep(sleep_s)
    return prs


def iter_text_sources(
    pr: PullRequest,
    sleep_s: float
) -> Iterable[Tuple[str, str, str, str, str]]:
    pr_user = pr.user
    pr_login = pr_user.login if pr_user else ""
    pr_type = pr_user.type if pr_user else ""
    pr_date = pr.created_at.isoformat() if pr.created_at else ""

    yield ("title", pr.title or "", pr_login, pr_type, pr_date)
    yield ("body", pr.body or "", pr_login, pr_type, pr_date)

    for c in pr.get_issue_comments():
        u = c.user
        yield (
            f"issue_comment:{c.id}",
            c.body or "",
            (u.login if u else ""),
            (u.type if u else ""),
            c.created_at.isoformat() if c.created_at else "",
        )
        if sleep_s:
            time.sleep(sleep_s)

    for rc in pr.get_review_comments():
        u = rc.user
        yield (
            f"review_comment:{rc.id}",
            rc.body or "",
            (u.login if u else ""),
            (u.type if u else ""),
            rc.created_at.isoformat() if rc.created_at else "",
        )
        if sleep_s:
            time.sleep(sleep_s)

    # PR commits: scan commit messages
    for cm in pr.get_commits():
        msg = (cm.commit.message or "")

        actor_login = ""
        actor_type = ""

        try:
            if cm.author is not None:
                # Accessing login might raise IncompletableObject in some cases
                actor_login = cm.author.login or ""
                actor_type = cm.author.type or ""
        except IncompletableObject:
            actor_login = ""
            actor_type = ""

        if not actor_login:
            if cm.commit.author and cm.commit.author.name:
                actor_login = cm.commit.author.name
                actor_type = "User"
            elif cm.commit.committer and cm.commit.committer.name:
                actor_login = cm.commit.committer.name
                actor_type = "User"

        dt = ""
        if cm.commit.author and cm.commit.author.date:
            dt = cm.commit.author.date.isoformat()
        elif cm.commit.committer and cm.commit.committer.date:
            dt = cm.commit.committer.date.isoformat()

        yield (f"commit:{cm.sha}", msg, actor_login, actor_type, dt)
        if sleep_s:
            time.sleep(sleep_s)


def make_snippet(text: str, start: int, end: int, context: int = 80) -> str:
    left = max(0, start - context)
    right = min(len(text), end + context)
    return text[left:right].replace("\n", " ").strip()


def scan_repo(repo_full_name: str, state: str, max_per_pattern: int, sleep_s: float, key_token: int) -> List[Match]:
    auth = Auth.Token(KEYS[int(key_token)])
    gh = Github(auth=auth, per_page=100)
    repo: Repository = gh.get_repo(repo_full_name)

    matches: List[Match] = []

    pr_cache: Dict[int, PullRequest] = {}
    processed_pr_numbers: Set[int] = set()

    for pname, pregex in PATTERNS.items():
        token_query = extract_search_tokens(pname, pregex)
        candidates = search_candidate_prs(
            gh, repo_full_name, token_query, state, max_per_pattern, sleep_s
        )

        for pr_stub in candidates:
            if pr_stub.number not in pr_cache:
                pr_cache[pr_stub.number] = repo.get_pull(pr_stub.number)

            pr = pr_cache[pr_stub.number]

            if pr.number not in processed_pr_numbers:
                processed_pr_numbers.add(pr.number)
                pr._cached_text_sources = list(iter_text_sources(pr, sleep_s))  

            for where, text, actor_login, actor_type, mentioned_at in pr._cached_text_sources: 
                for m in pregex.finditer(text):
                    matches.append(
                        Match(
                            pattern_name=pname,
                            pr_number=pr.number,
                            pr_url=pr.html_url,
                            where=where,
                            match_text=m.group(0),
                            snippet=make_snippet(text, m.start(), m.end()),
                            actor_login=actor_login,
                            actor_type=actor_type,
                            mentioned_at=mentioned_at,
                        )
                    )

    return matches


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", choices=["all", "open", "closed", "merged"], default="all")
    ap.add_argument("--max-per-pattern", type=int, default=200)
    ap.add_argument("--sleep", type=float, default=0.2)
    ap.add_argument("--repos-json")
    ap.add_argument("--out-csv", default="augmented_mentions.csv")
    ap.add_argument("--github-token", help="GitHub API token (overrides GITHUB_TOKEN env var)")
    args = ap.parse_args()

    # if args.github_token:
    #     KEY_INDEX = args.github_token
    #     os.environ["GITHUB_TOKEN"] = args.github_token

    repos: List[str] = []
    if args.repos_json:
        with open(args.repos_json) as f:
            for r in json.load(f):
                repos.append(r.replace("https://github.com/", "").rstrip("/"))
    else:
        raise SystemExit("You must provide --repos-json")

    # Open CSV once
    with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "repo",
            "pattern",
            "pr_number",
            "pr_url",
            "where",
            "match_text",
            "mentioned_at",
            "actor_login",
            "actor_type",
            "snippet",
        ])

        # Process repos one by one
        for r in repos:
            start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{start_ts}] collecting {r}", flush=True)

            repo_matches = scan_repo(
                r,
                args.state,
                args.max_per_pattern,
                args.sleep,
                args.github_token
            )

            for m in repo_matches:
                writer.writerow([
                    r,
                    m.pattern_name,
                    m.pr_number,
                    m.pr_url,
                    m.where,
                    m.match_text,
                    m.mentioned_at,
                    m.actor_login,
                    m.actor_type,
                    m.snippet,
                ])

            # Ensure data is written after each repo
            f.flush()

            print(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] finished {r} "
                f"({len(repo_matches)} matches)",
                flush=True,
            )

    print(f"Results written incrementally to {args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
