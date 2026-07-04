import json
import argparse
import sys

from github_collector import (
    collect_github_evidence,
    GithubRateLimitError
)

def main():
    parser = argparse.ArgumentParser(
        description="GitHub 릴리스 계보 증거 수집기"
    )

    parser.add_argument(
        "owner_repo",
        help="GitHub 저장소 이름. 예: expressjs/express"
    )

    parser.add_argument(
        "git_head",
        help="npm registry에서 가져온 gitHead commit SHA"
    )

    args = parser.parse_args()

    try:
        result = collect_github_evidence(
            owner_repo=args.owner_repo,
            git_head=args.git_head
        )

        print(json.dumps(result, indent=2, ensure_ascii=False))

    except GithubRateLimitError as e:
        error_result = {
            "status": "UNVERIFIABLE",
            "reason": "GITHUB_RATE_LIMIT_EXCEEDED",
            "message": str(e),
            "repository": args.owner_repo,
            "git_head": args.git_head
        }

        print(json.dumps(error_result, indent=2, ensure_ascii=False))
        sys.exit(2)

    except RuntimeError as e:
        error_result = {
            "status": "ERROR",
            "reason": "CONFIG_ERROR",
            "message": str(e)
        }

        print(json.dumps(error_result, indent=2, ensure_ascii=False))
        sys.exit(1)

    except Exception as e:
        error_result = {
            "status": "ERROR",
            "reason": "GITHUB_COLLECT_FAILED",
            "message": str(e),
            "repository": args.owner_repo,
            "git_head": args.git_head
        }

        print(json.dumps(error_result, indent=2, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main()