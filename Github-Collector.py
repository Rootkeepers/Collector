import os
from github import Github

TOKEN = os.getenv("GITHUB_TOKEN")
g = Github(TOKEN)

def check_github_rate_limit():
    overview = g.get_rate_limit()
    rate = overview.rate

    reset_time = rate.reset.strftime("%Y-%m-%d %H:%M:%S")

    if rate.remaining == 0:
        print("\n[오류] GitHub API Rate Limit을 초과했습니다.")
        print(f"{reset_time} 시간 이후 다시 시도해주세요.")
    elif rate.remaining <= 10:
        print(f"\n[경고] 남은 API 요청 횟수가 {rate.remaining}회입니다.")
    else:
        print("\nAPI를 정상적으로 사용할 수 있습니다.")

check_github_rate_limit()
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

for info in commit_info:
    print(f"Tag: {info['tag']}")
    print(f"SHA: {info['sha']}")
    print(f"Author: {info['author']}")
    print(f"Timestamp: {info['timestamp']}")
    print()