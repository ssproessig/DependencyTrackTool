import argparse
import itertools
import logging
import re
from datetime import UTC

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


TIMEOUT = 30.0


########################################################################################################################


class BaseAction:
    def execute(self, _dependency_track):
        logger.warning("not implemented")


class CleanGitFlowShortLivingBranches(BaseAction):
    LONG_LIVING_BRANCHES = [
        # git-flow
        "^master$",
        "develop",
        # maven release artifacts
        "\\d+\\.\\d+\\.\\d+",
    ]
    SHORT_LIVING_BRANCHES = [
        # git-flow
        "^PR-\\d+$",
        # maven snapshot artifacts
        "\\d+\\.\\d+\\.\\d+-SNAPSHOT$",
    ]

    def __init__(self, _arguments):
        self.LONG_LIVING_BRANCHES = [re.compile(slb) for slb in self.LONG_LIVING_BRANCHES]
        self.SHORT_LIVING_BRANCHES = [re.compile(slb) for slb in self.SHORT_LIVING_BRANCHES]

        parser = argparse.ArgumentParser()
        parser.add_argument("--filter-project-name", help="project name must match (default: any name)", default=".*")
        args = parser.parse_args(_arguments)

        self._matching_project_name = re.compile(args.filter_project_name)

    def execute(self, dependency_track):
        for project in dt.get_projects():
            if project.version is None:
                logger.info("Skipping '%s' [%s] as it does not carry a version", project.name, project.uuid)
                continue

            if not self._matching_project_name.fullmatch(project.name):
                logger.info("Skipping '%s' as it does not match project name filter", project)
                continue

            if any(slb.fullmatch(project.version) for slb in self.LONG_LIVING_BRANCHES):
                logger.info("Skipping '%s' as it is on a long-living branch ", project)
                continue

            if any(slb.fullmatch(project.version) for slb in self.SHORT_LIVING_BRANCHES):
                if not dependency_track.delete_project(project):
                    logger.warning("Unable to delete %s", project)
                continue

            logger.info(
                "Skipping '%s' as it is neither a LONG- nor SHORT-living branch version - and I don't know what to do",
                project,
            )


# inspired by code by David Nascimento
class CreateVulnerabilityReport(BaseAction):
    class XlsxWriter:
        COLUMN_WIDTH_SCALING = 4

        def __init__(self, _report):
            import xlsxwriter

            filename = f"Vulnerability-Report_{_report.release_tag}-{_report.created_at.strftime('%d%m%Y_%H%M%S')}.xlsx"
            logger.info("writing to %s...", filename)

            xlsx = xlsxwriter.Workbook(filename)
            xlsx.formats[0].set_font_name("Consolas")
            xlsx.formats[0].set_font_size("9")
            self._heading = xlsx.add_format({"bold": True})
            self._write_summary(xlsx, _report)
            xlsx.close()

            logger.info("...ready.")

        def _escape_name(self, in_name):
            out_name = in_name
            for c in ["[", "]", ":", "*", "?", "/", "\\"]:
                out_name = out_name.replace(c, "_")
            return out_name

        def _write_sheet(self, _xlsx, _name, _headers, _rows, _row_callback=None):
            sheet = _xlsx.add_worksheet(self._escape_name(_name[:31]))

            for idx, header in enumerate(_headers.values()):
                sheet.write(0, idx, header, self._heading)

            for row_idx, row in enumerate(_rows, start=1):
                column_value_max_length = {}

                for col_idx, field in enumerate(_headers.keys()):
                    value = getattr(row, field, "n/a")
                    sheet.write(row_idx, col_idx, value)
                    column_value_max_length[col_idx] = max(column_value_max_length.get(col_idx, 0), len(str(value)))

                for col_idx in range(len(column_value_max_length)):
                    sheet.set_column(col_idx, col_idx, column_value_max_length[col_idx] * self.COLUMN_WIDTH_SCALING)

                if _row_callback:
                    _row_callback(row)

            return sheet

        def _write_summary(self, _xlsx, _report):
            summary_sheet_fields = {
                "name": "Project Name",
                "version": "Version",
                "vulnerabilities": "Vulnerabilities",
                "vulnerableComponents": "Vulnerable Components",
                "components": "Components",
                "inheritedRiskScore": "Risk Score",
            }

            summary_sheet = self._write_sheet(
                _xlsx,
                "Summary",
                summary_sheet_fields,
                _report.projects,
                lambda project: self._write_project_sheet(_xlsx, project),
            )

            summary_sheet.conditional_format(
                0,
                len(summary_sheet_fields) - 1,
                10000,
                len(summary_sheet_fields) - 1,
                {
                    "type": "icon_set",
                    "icon_style": "3_traffic_lights",
                    "reverse_icons": True,
                    "icons": [
                        {"criteria": ">=", "type": "number", "value": 10},
                        {"criteria": ">", "type": "number", "value": 0},
                        {"criteria": "<=", "type": "number", "value": 0},
                    ],
                },
            )

        def _write_project_sheet(self, _xlsx, _project):
            self._write_sheet(
                _xlsx,
                f"{_project.name} {_project.version}"[:31],
                {
                    "name": "Name",
                    "version": "Version",
                    "license": "Under License",
                    "purl": "PURL",
                    "sha256": "Checksum",
                },
                _project.dependencies,
            )

    SUPPORTED_WRITERS = {"xlsx": XlsxWriter}

    class Report:
        def __init__(self, _release_tag):
            from datetime import datetime

            self.created_at = datetime.now(tz=UTC)
            self.release_tag = _release_tag
            self.projects = []

    class ReportedProject:
        REPORT_FIELDS = ["name", "version"]
        METRIC_FIELDS = ["vulnerabilities", "vulnerableComponents", "components", "inheritedRiskScore"]

        def __init__(self, _project):
            [self.__setattr__(name, _project[name]) for name in self.REPORT_FIELDS]
            [self.__setattr__(name, _project.metrics[name]) for name in self.METRIC_FIELDS]
            self.dependencies = []

        def __repr__(self):
            return f"{self.name}:{self.version} with {self.vulnerabilities} vulnerabilities"

    def __init__(self, _arguments):
        parser = argparse.ArgumentParser()
        parser.add_argument("--tag", help="the tag to filter projects for reporting")
        parser.add_argument(
            "--writer",
            default="xlsx",
            help=f"the writer to use for reporting: {self.SUPPORTED_WRITERS.keys()}",
        )
        args = parser.parse_args(_arguments)

        if args.writer not in self.SUPPORTED_WRITERS:
            msg = f"not a supported writer: {args.writer}"
            raise KeyError(msg)

        self._release_tag = args.tag
        self._writer = args.writer

    def execute(self, _dependency_track):
        report = self.Report(self._release_tag)

        tagged_projects = dt.get_projects_with_tag(self._release_tag)
        logger.info("%d reported projects for %s", len(tagged_projects), self._release_tag)

        for _project in tagged_projects:
            logger.info("--> Collecting metrics for %s", _project)
            project_report = self.ReportedProject(_project)
            project_report.dependencies = dt.get_project_dependencies(_project)

            report.projects.append(project_report)

        self.SUPPORTED_WRITERS[self._writer](report)


_ACTIONS = {
    "clean-gitflow-short-living-branch-versions": CleanGitFlowShortLivingBranches,
    "create-vulnerability-report": CreateVulnerabilityReport,
}


########################################################################################################################


class Project(dict):
    def __init__(self, *args, **kwargs):
        args[0].setdefault("version", None)
        args[0].setdefault("uuid", None)
        super().__init__(*args, **kwargs)
        self.__dict__ = self

    def __repr__(self):
        return f"{self.name}:{self.version}"


class Component(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self

    def __repr__(self):
        return f"{self.purl}"


class InvalidResponseError(Exception):
    def __init__(self, response):
        self._response = response

    def __str__(self):
        return f"{self._response.status_code} for {self._response.url}: {self._response.text}"


class DependencyTrack:
    PAGE_SIZE = 100

    def __init__(self, _url, _api_key):
        self._api_key = _api_key
        self._url = f"{_url}/api/v1"
        self._shared_header = {
            "Content-Type": "application/json",
            "X-Api-key": self._api_key,
        }

        logger.info("Using DependencyTrack from %s", self._url)

    def _get_paged(self, url) -> list[dict]:
        objects = []

        for page in itertools.count(1):
            response = requests.get(
                url,
                headers=self._shared_header,
                params={"pageSize": self.PAGE_SIZE, "pageNumber": page},
                timeout=TIMEOUT,
            )

            if not response.ok:
                raise InvalidResponseError(response)

            objects_on_page = response.json()

            if objects_on_page:
                objects += objects_on_page
            else:
                break

        return objects

    def get_projects(self) -> list[Project]:
        logger.info("Getting list of projects")
        return [Project(p) for p in self._get_paged(f"{self._url}/project")]

    def delete_project(self, _project) -> bool:
        logger.info("Deleting project %s", _project)
        resp = requests.delete(
            f"{self._url}/project/{_project['uuid']}",
            headers=self._shared_header,
            timeout=TIMEOUT,
        )
        return resp.ok

    def get_projects_with_tag(self, _release_tag) -> list[Project]:
        logger.info("Getting list of projects with tag %s", _release_tag)

        return [
            Project(p)
            for p in requests.get(
                f"{self._url}/project/tag/{_release_tag}",
                headers=self._shared_header,
                timeout=TIMEOUT,
            ).json()
        ]

    def get_project_dependencies(self, _project) -> list[Component]:
        logger.info("Getting list of project dependencies for %s", _project)
        return [Component(d) for d in self._get_paged(f"{self._url}/component/project/{_project.uuid}")]


########################################################################################################################


if __name__ == "__main__":
    app_parser = argparse.ArgumentParser(description="DependencyTrack tools")
    app_parser.add_argument("--url", required=True, help="Dependency Track URL to use")
    app_parser.add_argument("--api-key", required=True, help="Dependency Track API key to use")
    app_parser.add_argument("action", help=f"Action to execute: {' '.join(_ACTIONS.keys())}")
    app_parser.add_argument("remaining_arguments", nargs=argparse.REMAINDER)

    arguments = app_parser.parse_args()

    try:
        action = _ACTIONS[arguments.action](arguments.remaining_arguments)

        # noinspection PyBroadException
        try:
            dt = DependencyTrack(arguments.url, arguments.api_key)
            action.execute(dt)

        except Exception as ex:
            logger.fatal(f"executing {arguments.action} failed: {ex}")

    except KeyError:
        logger.fatal(f"unknown action {arguments.action}")
