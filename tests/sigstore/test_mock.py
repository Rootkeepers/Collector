"""cross_validator가 predicate와 OIDC의 불일치를 잡아내는지 확인한다.

네트워크를 타지 않는다 — workflow_path를 일부러 비운 가짜 데이터를 넣고
검증이 실패로 떨어지는지만 본다.

실행: python tests/sigstore/test_mock.py
"""

from rootkeepers.collectors.sigstore.cross_validator import validate_oidc_matches_predicate

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