# Dependency Track Automation tool
Use this tool to automate recurring tasks via the Dependency Track API.

## Prerequisites
- have a recent Python 3 interpreter on the `PATH`
- be sure to install all dependencies, e.g. via `pip install -r requirements.txt`
- have an API key to access Dependency Track's API

## Usage
```
> dependency_track-automation.py --help
> ...help output...

> dependency_track-automation.py --url http://ngtms-cd:8082 --api-key YOUR_SECRET_API_KEY  ACTION_TO_EXECUTE
```

where `ACTION_TO_EXECUTE` is one of the _Supported Actions._

## Supported Actions

### clean-gitflow-short-living-branch-versions
This action will iterate all projects on the Dependency Track server. Any project whose `version`
does not match a _long-living branch_ according to git-flow will be deleted.

Merely a cleanup action for our git-flow based Jenkins CI/CD, to be executed once a sprint is
finished.

```
> dependency_track-automation.py --url http://10.220.163.57:8080 --api-key YOUR_SECRET_API_KEY  clean-gitflow-short-living-branch-versions  --filter-project-name  aramis.*
...
2021-06-03 13:07:44,146 - root - INFO - Using DependencyTrack from http://10.220.163.57:8080/api/v1
2021-06-03 13:07:44,147 - root - INFO - Getting list of projects
2021-06-03 13:07:44,370 - root - INFO - Skipping 'aramis-o.api-server:develop' as it is on a long-living branch 
2021-06-03 13:07:44,370 - root - INFO - Deleting 'aramis-o.api-server:PR-117' 
2021-06-03 13:07:44,371 - root - INFO - Skipping 'asrs:1.2.1-SNAPSHOT' as it does not match project name filter
...
```


### create-vulnerability-report
This action will iterator the Dependency Track server for all projects that carry a given tag. For those projects found
it will collect the components used and their license and vulnerability status.

Use the parameters
- `tag` to specify the _tag_ to query projects for
- `writer` to specify the output format to write in; currently supported:
    - `xlsx` for Microsoft Excel

```
> dependency_track-automation.py --url http://ngtms-cd:8082 --api-key YOUR_SECRET_API_KEY  create-vulnerability-report  -- --tag MY_APP_1_0_0 --writer xlsx
...
2021-02-05 16:55:29,062 - root - INFO - writing to Vulnerability-Report_MY_APP_1_0_0-05022021_165528.xlsx...
2021-02-05 16:55:29,102 - root - INFO - ...ready.
```
