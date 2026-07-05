from cross_validator import validate_oidc_matches_predicate

# 가짜 SLSA 데이터 (workflow_path를 일부러 뺌)
mock_predicate = {
    "repository": "rootkeepers/test",
    "workflow_path": ""  # 고의 누락
}

# 가짜 OIDC 데이터
mock_oidc = {
    "subject_repo": "rootkeepers/test",
    "subject_workflow": ".github/workflows/build.yml",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:rootkeepers/test"
}

result = validate_oidc_matches_predicate(mock_predicate, mock_oidc)
print(f"검증 통과 여부: {result['passed']}")
print(f"불일치 사유: {result['mismatches'][0]['message']}")