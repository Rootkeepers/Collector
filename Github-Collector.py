import os
from github import Github

repo, g = ''

def get_package():
    TOKEN = os.getenv("GITHUB_TOKEN")
    g = Github(TOKEN)
    repo = g.get_repo("expressjs/express") # 패키지 리포 받아와야함
    # 테스트용 패키지

#======================================================
# GitHub API의 Rate Limit 상태를 확인 및 경고 메시지 출력
#======================================================
def collect_rate_limit():
    overview = g.get_rate_limit() # rate_limit 받아오기
    rate = overview.rate
    reset_time = rate.reset.strftime("%Y-%m-%d %H:%M:%S") # 토큰 초기화 시간

    if rate.remaining == 0:
        print("\n[오류] GitHub API Rate Limit을 초과했습니다.")
        print(f"{reset_time} 시간 이후 다시 시도해주세요.")
        exit()
    elif rate.remaining <= 10:
        print(f"\n[경고] 남은 API 요청 횟수가 {rate.remaining}회입니다.")
    get_package()


#======================================
# commit 정보 바탕으로 PR 정보 가져오기
#======================================
def collect_PR(commit):
    PR_info = []

    try:
        pulls = commit.get_pulls()

        for i, pr in enumerate(pulls):
            if i >= 10:
                break

            PR_info.append({
                "number": pr.number,
                "title": pr.title,
                "merged": pr.merged,
                "merged_at": pr.merged_at
            })

    except Exception as e:
        print("PR 실패:", e)

    return PR_info

#==========================
# commit 관련 정보 받아오기
#==========================
def collect_commit():
    commit_info = []

    try:
        tags = repo.get_tags()

        for i, tag in enumerate(tags):
            if i >= 10:
                break

            try:
                commit = repo.get_commit(tag.commit.sha)

                commit_info.append({
                    "tag": tag.name,
                    "sha": commit.sha,
                    "author": commit.commit.author.name if commit.commit.author else None,
                    "timestamp": commit.commit.author.date.strftime("%Y-%m-%d %H:%M:%S") if commit.commit.author else None,
                    "pull_requests": collect_PR(commit)
                })

            except Exception as e:
                print("commit 실패:", e)
                continue

    except Exception as e:
        print("tag 조회 실패:", e)

    return commit_info

#============================
# workflow 관련 정보 받아오기
#============================
def collect_workflow():
    workflow_info = []
    runs = repo.get_workflow_runs()

    for i, run in enumerate(runs):
        if i >= 10:
            break

        workflow_info.append({
            "id": run.raw_data["workflow_id"],
            "name": run.name,
            "repository": repo.full_name,
            "run_id": run.id,
            "builder": run.actor.login if run.actor else None
        })
    return workflow_info