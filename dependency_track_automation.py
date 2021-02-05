import logging
from typing import List

import requests

logging.basicConfig(level=logging.INFO)


########################################################################################################################


class BaseAction:
    def execute(self, dependency_track):
        logging.warning("not implemented")


class CleanGitFlowShortLivingBranches(BaseAction):
    LONG_LIVING_BRANCHES = ["master", "develop"]

    def execute(self, dependency_track):
        for project in dt.get_projects():
            if project.version in self.LONG_LIVING_BRANCHES:
                logging.info(f"Skipping long-living branch {project}")
                continue

            if not dependency_track.delete_project(project):
                logging.warning(f"Unable to delete {project}")


_ACTIONS = {
    "clean-gitflow-short-living-branch-versions": CleanGitFlowShortLivingBranches
}


########################################################################################################################


class Project(dict):
    def __init__(self, *args, **kwargs):
        super(Project, self).__init__(*args, **kwargs)
        self.__dict__ = self

    def __str__(self):
        return f"{self.name}:{self.version}"


class DependencyTrack:
    def __init__(self, _url, _api_key):
        self._api_key = _api_key
        self._url = f"{_url}/api/v1"
        self._shared_header = {
            "Content-Type": "application/json",
            "X-Api-key": self._api_key
        }

        logging.info(f"Using DependencyTrack from {self._url}")

    def get_projects(self) -> List[Project]:
        logging.info(f"Getting list of projects")
        return [Project(p) for p in requests.get(f"{self._url}/project", headers=self._shared_header).json()]

    def delete_project(self, _project) -> bool:
        logging.info(f"Deleting project {_project}")
        resp = requests.delete(f"{self._url}/project/{_project['uuid']}", headers=self._shared_header)
        return resp.ok


########################################################################################################################


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DependencyTrack tools")
    parser.add_argument('--url', required=True, help="Dependency Track URL to use")
    parser.add_argument('--api-key', required=True, help="Dependency Track API key to use")
    parser.add_argument('action', help=f"Action to execute: {' '.join(_ACTIONS.keys())}")

    arguments = parser.parse_args()

    try:
        action = _ACTIONS[arguments.action]()

        # noinspection PyBroadException
        try:
            dt = DependencyTrack(arguments.url, arguments.api_key)
            action.execute(dt)

        except Exception as ex:
            logging.fatal(f"executing {arguments.action} failed: {ex}")

    except KeyError:
        logging.fatal(f"unknown action {arguments.action}")
