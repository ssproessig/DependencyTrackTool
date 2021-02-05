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
