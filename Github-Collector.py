import os
from github import Github

TOKEN = os.getenv("GITHUB_TOKEN")
g = Github(TOKEN)

def collect_rate_limit(): # GitHub API의 Rate Limit 상태를 확인 및 경고 메시지 출력
    overview = g.get_rate_limit()
    rate = overview.rate
    reset_time = rate.reset.strftime("%Y-%m-%d %H:%M:%S") # 토큰 초기화 시간

    if rate.remaining == 0:
        print("\n[오류] GitHub API Rate Limit을 초과했습니다.")
        print(f"{reset_time} 시간 이후 다시 시도해주세요.")
        exit()
    elif rate.remaining <= 10:
        print(f"\n[경고] 남은 API 요청 횟수가 {rate.remaining}회입니다.")

def collect_commit():
    repo = g.get_repo("expressjs/express") # 패키지 리포 받아와야함
    # 테스트용 패키지
    tags = repo.get_tags() # 리포 태그 받아오기
    commit_info = []

    for i, tag in enumerate(repo.get_tags()):
        if i >= 10:
            break

        commit = repo.get_commit(tag.commit.sha)
        commit_info.append({
            "tag": tag.name,
            "sha": commit.sha,
            "author": commit.commit.author.name,
            "timestamp": commit.commit.author.date.strftime("%Y-%m-%d %H:%M:%S")
        })
