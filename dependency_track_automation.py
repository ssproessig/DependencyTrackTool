import argparse
import itertools
import logging
from typing import List

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


########################################################################################################################


class BaseAction:
    def execute(self, dependency_track):
        logging.warning("not implemented")


class CleanGitFlowShortLivingBranches(BaseAction):
    LONG_LIVING_BRANCHES = ["master", "develop"]

    def __init__(self, _arguments):
        pass  # nothing to configure yet

    def execute(self, dependency_track):
        for project in dt.get_projects():
            if project.version in self.LONG_LIVING_BRANCHES:
                logging.info(f"Skipping long-living branch {project}")
                continue

            if not dependency_track.delete_project(project):
                logging.warning(f"Unable to delete {project}")


# inspired by code by David Nascimento
class CreateVulnerabilityReport(BaseAction):
    class XlsxWriter:
        def __init__(self, _report):
            import xlsxwriter

            filename = \
                f"Vulnerability-Report_{_report.release_tag}-{_report.created_at.strftime('%d%m%Y_%H%M%S')}.xlsx"
            logging.info(f"writing to {filename}...")

            xlsx = xlsxwriter.Workbook(filename)
            xlsx.formats[0].set_font_name("Consolas")
            xlsx.formats[0].set_font_size("9")
            self._heading = xlsx.add_format({'bold': True})
            self._write_summary(xlsx, _report)
            xlsx.close()

            logging.info("...ready.")

        def _write_sheet(self, _xlsx, _name, _headers, _rows, _row_callback=None):
            sheet = _xlsx.add_worksheet(_name[:31])

            for idx, header in enumerate(_headers.values()):
                sheet.write(0, idx, header, self._heading)

            for row_idx, row in enumerate(_rows, start=1):
                for col_idx, field in enumerate(_headers.keys()):
                    sheet.write(row_idx, col_idx, getattr(row, field, "n/a"))

                if _row_callback:
                    _row_callback(row)

            return sheet

        def _write_summary(self, _xlsx, _report):
            summary_sheet_fields = {
                'name': 'Project Name',
                'version': 'Version',
                'vulnerabilities': 'Vulnerabilities',
                'vulnerableComponents': 'Vulnerable Components',
                'components': 'Components',
                'inheritedRiskScore': 'Risk Score'
            }

            summary_sheet = self._write_sheet(
                _xlsx, "Summary", summary_sheet_fields, _report.projects,
                lambda project: self._write_project_sheet(_xlsx, project)
            )

            summary_sheet.conditional_format(
                0, len(summary_sheet_fields) - 1, 10000, len(summary_sheet_fields) - 1,
                {'type': 'icon_set',
                 'icon_style': '3_traffic_lights',
                 'reverse_icons': True,
                 'icons': [{'criteria': '>=', 'type': 'number', 'value': 10},
                           {'criteria': '>', 'type': 'number', 'value': 0},
                           {'criteria': '<=', 'type': 'number', 'value': 0}]}
            )

        def _write_project_sheet(self, _xlsx, _project):
            self._write_sheet(_xlsx, f"{_project.name} {_project.version}"[:31], {
                'purl': 'PURL',
                'classifier': 'Classifier',
                'sha256': 'Checksum',
                'license': 'Under License'
            }, _project.dependencies)

    SUPPORTED_WRITERS = {
        "xlsx": XlsxWriter
    }

    class Report:
        def __init__(self, _release_tag):
            from datetime import datetime
            self.created_at = datetime.now()
            self.release_tag = _release_tag
            self.projects = []

    class ReportedProject:
        REPORT_FIELDS = ['name', 'version']
        METRIC_FIELDS = ['vulnerabilities', 'vulnerableComponents', 'components', 'inheritedRiskScore']

        def __init__(self, _project):
            [self.__setattr__(name, _project[name]) for name in self.REPORT_FIELDS]
            [self.__setattr__(name, _project.metrics[name]) for name in self.METRIC_FIELDS]
            self.dependencies = []

        def __repr__(self):
            return f"{self.name}:{self.version} with {self.vulnerabilities} vulnerabilities"

    def __init__(self, _arguments):
        parser = argparse.ArgumentParser()
        parser.add_argument("--tag", help="the tag to filter projects for reporting")
        parser.add_argument("--writer", default='xlsx',
                            help=f"the writer to use for reporting: {self.SUPPORTED_WRITERS.keys()}")
        args = parser.parse_args(_arguments)

        if args.writer not in self.SUPPORTED_WRITERS:
            raise KeyError(f"not a supported writer: {args.writer}")

        self._release_tag = args.tag
        self._writer = args.writer

    def execute(self, dependency_track):
        report = self.Report(self._release_tag)

        tagged_projects = dt.get_projects_with_tag(self._release_tag)
        logging.info(f"{len(tagged_projects)} reported projects for {self._release_tag}")

        for _project in tagged_projects:
            logging.info(f"--> Collecting metrics for {_project}")
            project_report = self.ReportedProject(_project)
            project_report.dependencies = dt.get_project_dependencies(_project)

            report.projects.append(project_report)

        self.SUPPORTED_WRITERS[self._writer](report)


_ACTIONS = {
    "clean-gitflow-short-living-branch-versions": CleanGitFlowShortLivingBranches,
    "create-vulnerability-report": CreateVulnerabilityReport
}


########################################################################################################################


class Project(dict):
    def __init__(self, *args, **kwargs):
        super(Project, self).__init__(*args, **kwargs)
        self.__dict__ = self

    def __repr__(self):
        return f"{self.name}:{self.version}"


class Component(dict):
    def __init__(self, *args, **kwargs):
        super(Component, self).__init__(*args, **kwargs)
        self.__dict__ = self

    def __repr__(self):
        return f"{self.purl}"


class DependencyTrack:
    PAGE_SIZE = 100

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

    def get_projects_with_tag(self, _release_tag) -> List[Project]:
        logging.info(f"Getting list of projects with tag {_release_tag}")

        return [Project(p) for p in
                requests.get(f"{self._url}/project/tag/{_release_tag}", headers=self._shared_header).json()]

    def get_project_dependencies(self, _project) -> List[Component]:
        logging.info(f"Getting list of project dependencies for {_project}")

        all_dependencies = []

        for page in itertools.count(1):
            dependencies = requests.get(
                f"{self._url}/dependency/project/{_project.uuid}",
                headers=self._shared_header,
                params={"pageSize": self.PAGE_SIZE, "pageNumber": page}
            ).json()

            if dependencies:
                all_dependencies += dependencies
            else:
                break

        return [Component(d['component']) for d in all_dependencies]


########################################################################################################################


if __name__ == "__main__":
    app_parser = argparse.ArgumentParser(description="DependencyTrack tools")
    app_parser.add_argument('--url', required=True, help="Dependency Track URL to use")
    app_parser.add_argument('--api-key', required=True, help="Dependency Track API key to use")
    app_parser.add_argument('action', help=f"Action to execute: {' '.join(_ACTIONS.keys())}")
    app_parser.add_argument('remaining_arguments', nargs=argparse.REMAINDER)

    arguments = app_parser.parse_args()

    try:
        action = _ACTIONS[arguments.action](arguments.remaining_arguments)

        # noinspection PyBroadException
        try:
            dt = DependencyTrack(arguments.url, arguments.api_key)
            action.execute(dt)

        except Exception as ex:
            logging.fatal(f"executing {arguments.action} failed: {ex}")

    except KeyError:
        logging.fatal(f"unknown action {arguments.action}")
