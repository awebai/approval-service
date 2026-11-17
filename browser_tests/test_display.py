"""Render the actual approval row in Chromium, without a service or signers."""

import json
from importlib.resources import files
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

from approval_service.definitions import definition


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            browser.close()


@pytest.fixture
def row(browser):
    assets = files("approval_service").joinpath("assets")
    html = (
        assets.joinpath("index.html")
        .read_text()
        .replace('<script type="module" src="/assets/app.mjs"></script>', "")
    )
    cases = json.loads(
        (Path(__file__).parents[1] / "vectors/enforcer-requester-v1.json").read_text()
    )["cases"]
    case = next(c for c in cases if c["id"] == "presentation-exact-caller")
    item = {
        "request": case["request"],
        "digest": case["needs_human"]["digest"],
        "display": definition("human.add")["display"],
    }
    page = browser.new_page()
    try:
        page.set_content(html)
        # Expose the real module's private renderer, without replacing any DOM
        # behavior, requests, trust reader or approval-service implementation.
        page.add_script_tag(
            type="module",
            content=assets.joinpath("app.mjs").read_text()
            + "\nwindow.renderApprovalForTest = display;",
        )
        page.evaluate(
            "item => document.querySelector('#requests').append(window.renderApprovalForTest(item))",
            item,
        )
        yield page.locator("#requests article"), item, page
    finally:
        page.close()


def test_digest_and_other_string_values_are_plain(row):
    article, item, _ = row
    assert article.count() == 1
    for value in (
        item["digest"],
        item["request"]["organisation"],
        item["request"]["enforcer"]["audience"],
        item["request"]["act"]["target"]["person"],
    ):
        assert article.get_by_text(value, exact=True).count() == 1
        assert article.get_by_text(json.dumps(value), exact=True).count() == 0


def test_structured_values_keep_their_json_types(row):
    article, item, _ = row
    technical = article.locator("pre").all_text_contents()
    for value in (item["request"]["requester"], item["request"]["act"]):
        assert json.dumps(value, indent=2) in technical
    assert str(item["request"]["act"]["expected_revision"]) in technical


def test_plain_strings_remain_text_not_markup(row):
    _, item, page = row
    value = '<img src=x onerror="window.injected=true">'
    item["request"]["organisation"] = value
    page.evaluate(
        "item => document.querySelector('#requests').replaceChildren(window.renderApprovalForTest(item))",
        item,
    )
    article = page.locator("#requests article")
    assert article.get_by_text(value, exact=True).count() == 1
    assert article.locator("img").count() == 0
    assert page.evaluate("window.injected === undefined")


def test_admission_labels_the_effect_organisation_separately_from_home(row):
    _, item, page = row
    item["display"] = definition("organisation.person.admit")["display"]
    item["request"]["organisation"] = "approver-home.example"
    item["request"]["act"]["target"] = {
        "organisation": "organisation-being-joined.example",
        "person": "did:aw:hrCg7FYuHsoU5tqQ8r5JMUDHudr",
        "role": "member",
    }
    page.evaluate(
        "item => document.querySelector('#requests').replaceChildren(window.renderApprovalForTest(item))", item,
    )
    article = page.locator("#requests article")
    assert article.locator("p", has_text="Organisation being joined").count() == 1
    assert article.get_by_text("Organisation being joined", exact=True).locator("+ pre").inner_text() == "organisation-being-joined.example"
    assert article.get_by_text("Organisation", exact=True).locator("+ pre").inner_text() == "approver-home.example"
