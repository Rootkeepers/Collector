import os
from github import Github

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

#======================================================
# commit 정보 바탕으로 PR 정보 가져오기
#======================================================
def collect_PR(commit):
    PR_info = []
    pulls = commit.get_pulls()

    for i, pr in enumerate(pulls):
        if i >= 10:
            break

        PR_info.append({ # PR 숫자, 제목, merged 여부, merged 시간 저장
            "number": pr.number,
            "title": pr.title,
            "merged": pr.merged,
            "merged_at": pr.merged_at
        })
    return PR_info

#==========================
# commit 관련 정보 받아오기
#==========================
def collect_commit():
    commit_info = []

    for i, tag in enumerate(repo.get_tags()): # 최근 10개의 커밋 목록 받아오기
        if i >= 10:
            break
        commit = repo.get_commit(tag.commit.sha)
        commit_info.append({ # 태그, 커밋 sha, 작성자, 커밋 생성 날짜 저장
            "tag": tag.name,
            "sha": commit.sha,
            "author": commit.commit.author.name,
            "timestamp": commit.commit.author.date.strftime("%Y-%m-%d %H:%M:%S")
        })
    collect_PR(commit)
    return commit_info


collect_commit()