import os
from pathlib import Path

from dotenv import load_dotenv
from github import Github, Auth  # Auth 추가
from github import GithubException, BadCredentialsException, UnknownObjectException, RateLimitExceededException

load_dotenv(Path(__file__).resolve().parents[4] / ".env")

class GithubRateLimitError(Exception):
    pass

# ===============================
# GitHub repo 수집
# ===============================
def get_repo(owner_repo):
    token = os.getenv("GITHUB_TOKEN")

    if not token:  # GitHub token validation
        raise RuntimeError("GITHUB_TOKEN 환경변수가 없습니다.")

    try:  # GitHub repository access
        auth = Auth.Token(token)         # 토큰 객체 생성
        g = Github(auth=auth)            # 최신 방식으로 인증
        repo = g.get_repo(owner_repo)
        return g, repo

    except BadCredentialsException:  # Invalid GitHub credentials
        raise RuntimeError("GitHub 토큰이 잘못되었습니다.")

    except UnknownObjectException:  # Repository not found
        raise RuntimeError(f"Repository를 찾을 수 없습니다: {owner_repo}")

    except RateLimitExceededException:  # API rate limit exceeded
        raise GithubRateLimitError("GitHub API Rate Limit 초과")

    except GithubException as e:  # Other GitHub API errors
        raise RuntimeError(f"GitHub API 오류: {e}")

# ===========================
# GitHub API Rate Limit 확인
# ===========================
def collect_rate_limit(g):
    overview = g.get_rate_limit()
    rate = overview.rate

    # Collect rate limit information
    reset_time = rate.reset.strftime("%Y-%m-%d %H:%M:%S")

    if rate.remaining == 0:  # Rate limit exceeded
        raise GithubRateLimitError(
            f"GitHub API Rate Limit 초과. reset={reset_time}"
        )

    if rate.remaining <= 10:  # Low remaining requests warning
        print(f"[경고] 남은 API 요청 횟수가 {rate.remaining}회입니다.")

    # Return collected rate limit data
    return {
        "limit": rate.limit,          # Maximum API requests
        "remaining": rate.remaining,  # Remaining API requests
        "reset": reset_time           # Rate limit reset time
    }


# ==========================
# PR reviewer 정보 수집
# ==========================
def collect_reviewers(pr):
    reviewers = []

    try:  # Collect reviewer information
        reviews = pr.get_reviews()

        for i, review in enumerate(reviews):
            if i >= 10:
                break

            reviewers.append({
                "login": review.user.login if review.user else None,        # Reviewer username
                "state": review.state,                                      # Review status
                "approved": review.state == "APPROVED",                     # Approval result
                "submitted_at": review.submitted_at.isoformat()             # Review submission time
                if review.submitted_at else None
            })

    except Exception as e:  # Exception handling
        print("reviewer 실패:", e)

    return reviewers


# ======================================
# commit 정보 바탕으로 PR 정보 가져오기
# ======================================
def collect_PR(commit):
    pr_info = []

    try:  # Collect pull request information
        pulls = commit.get_pulls()

        for i, pr in enumerate(pulls):
            if i >= 10:
                break

            pr_info.append({
                "number": pr.number,                    # Pull request number
                "title": pr.title,                      # Pull request title
                "merged": pr.merged,                    # Merge status
                "merged_at": pr.merged_at.isoformat()   # Merge time
                if pr.merged_at else None,
                "reviewers": collect_reviewers(pr)  # Reviewer information
            })

    except Exception as e:  # Exception handling
        print("PR 실패:", e)

    return pr_info


# ==========================
# git_head 기준 commit 수집
# ==========================
def collect_commit(repo, git_head):
    try:  # Collect commit information
        commit = repo.get_commit(git_head)

        return {
            "sha": commit.sha,                  # Commit SHA
            "author": commit.commit.author.name # Commit author
            if commit.commit.author else None,
            "timestamp": commit.commit.author.date.isoformat()  # Commit timestamp
            if commit.commit.author else None,
            "pull_requests": collect_PR(commit) # Associated pull requests
        }

    except Exception as e:  # Exception handling
        print("commit 실패:", e)
        return None


# ==========================================
# git_head를 가리키는 tag가 있는지 확인
# ==========================================
def collect_matching_tags(repo, git_head):
    matched_tags = []

    try:  # Collect matching tag information
        tags = repo.get_tags()

        for i, tag in enumerate(tags):
            if i >= 10:
                break

            if tag.commit.sha == git_head:
                matched_tags.append({
                    "name": tag.name,          # Tag name
                    "sha": tag.commit.sha      # Associated commit SHA
                })

    except Exception as e:  # Exception handling
        print("tag 조회 실패:", e)

    return matched_tags


# ============================
# workflow 관련 정보 수집
# ============================
def collect_workflow(repo, git_head):
    workflow_info = []

    try:  # Collect workflow run information
        runs = repo.get_workflow_runs(head_sha=git_head)

        for i, run in enumerate(runs):
            if i >= 10:
                break

            workflow_info.append({
                "id": run.raw_data.get("workflow_id"),  # Workflow ID
                "name": run.name,                       # Workflow name
                "repository": repo.full_name,           # Repository name
                "run_id": run.id,                       # Workflow run ID
                "builder": run.actor.login if run.actor else None,  # Workflow trigger user
                "head_sha": run.head_sha,               # Commit SHA
                "event": run.event,                     # Trigger event
                "status": run.status,                   # Workflow status
                "conclusion": run.conclusion,           # Workflow result
                "created_at": run.created_at.isoformat()# Creation time
                if run.created_at else None,
                "updated_at": run.updated_at.isoformat()    # Last update time
                if run.updated_at else None
            })

    except Exception as e:  # Exception handling
        print("workflow 실패:", e)

    return workflow_info


# ============================
# GitHub evidence 통합 수집
# ============================
def collect_github_evidence(owner_repo, git_head):
    g, repo = get_repo(owner_repo)

    # Collect GitHub evidence
    rate_limit = collect_rate_limit(g)
    commit_info = collect_commit(repo, git_head)
    tag_info = collect_matching_tags(repo, git_head)
    workflow_info = collect_workflow(repo, git_head)

    # Return collected evidence
    return {
        "repository": repo.full_name,      # Repository name
        "rate_limit": rate_limit,          # Rate limit information
        "commit": commit_info,             # Commit information
        "tags": tag_info,                  # Matching tag information
        "workflows": workflow_info         # Workflow run information
    }
