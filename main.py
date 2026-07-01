from Github_Collector import (get_package, collect_rate_limit, collect_commit,collect_workflow)

get_package()
collect_rate_limit()

commit_info = collect_commit()
workflow_info = collect_workflow()