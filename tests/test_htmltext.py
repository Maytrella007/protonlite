"""Tests for flattening HTML mail into something readable."""

from __future__ import annotations

import unittest

from protonlite import htmltext


class Detection(unittest.TestCase):
    def test_mime_type_wins(self) -> None:
        self.assertTrue(htmltext.looks_like_html("hello", "text/html"))

    def test_sniffs_a_document(self) -> None:
        self.assertTrue(htmltext.looks_like_html("<!DOCTYPE html><html>..."))
        self.assertTrue(htmltext.looks_like_html("  <html lang='en'>"))

    def test_plain_text_is_left_alone(self) -> None:
        self.assertFalse(htmltext.looks_like_html("Dear William,\n\n3 < 5 & 4 > 2"))


class Conversion(unittest.TestCase):
    def test_drops_script_and_style(self) -> None:
        html = (
            "<html><head><style>.a{color:red}</style></head>"
            "<body><script>alert(1)</script><p>Only this.</p></body></html>"
        )
        self.assertEqual(htmltext.to_text(html), "Only this.")

    def test_keeps_paragraph_breaks(self) -> None:
        text = htmltext.to_text("<p>First.</p><p>Second.</p>")
        self.assertEqual(text, "First.\nSecond.")

    def test_br_breaks_the_line(self) -> None:
        self.assertEqual(htmltext.to_text("a<br>b"), "a\nb")

    def test_list_items_get_bullets(self) -> None:
        self.assertEqual(htmltext.to_text("<ul><li>one<li>two</ul>"), "- one\n- two")

    def test_unescapes_entities(self) -> None:
        self.assertEqual(htmltext.to_text("<p>3 &lt; 5 &amp; caf&eacute;</p>"), "3 < 5 & café")

    def test_collapses_runs_of_blank_lines(self) -> None:
        self.assertEqual(htmltext.collapse("a\n\n\n\n\nb"), "a\n\nb")

    def test_malformed_html_still_yields_text(self) -> None:
        out = htmltext.to_text("<div><p>text <b>bold</div></p></b>")
        self.assertIn("text", out)
        self.assertIn("bold", out)
        self.assertNotIn("<", out)

    def test_shrinks_a_marketing_email(self) -> None:
        html = "<html><body>" + "<table><tr><td>&nbsp;</td></tr></table>" * 200 + (
            "<p>Your statement is ready.</p></body></html>"
        )
        text = htmltext.to_text(html)
        self.assertIn("Your statement is ready.", text)
        self.assertLess(len(text), len(html) / 10)


class PlaintextToHtml(unittest.TestCase):
    def test_escapes_special_characters(self) -> None:
        out = htmltext.plaintext_to_html("a < b & c > d")
        self.assertIn("&lt;", out)
        self.assertIn("&amp;", out)
        self.assertIn("&gt;", out)
        self.assertNotIn("<b>", out)  # not interpreted as a tag

    def test_single_newline_becomes_a_break(self) -> None:
        out = htmltext.plaintext_to_html("one\ntwo")
        self.assertIn("one<br>", out)
        self.assertIn("two", out)

    def test_blank_line_starts_a_new_paragraph(self) -> None:
        out = htmltext.plaintext_to_html("para one\n\npara two")
        self.assertEqual(out.count("<p>"), 2)

    def test_round_trips_back_to_the_same_text(self) -> None:
        original = "Hello.\nThis is a < test > with & symbols.\n\nSecond paragraph."
        recovered = htmltext.to_text(htmltext.plaintext_to_html(original))
        self.assertIn("Hello.", recovered)
        self.assertIn("a < test > with & symbols.", recovered)
        self.assertIn("Second paragraph.", recovered)

    def test_empty_body_is_still_valid_html(self) -> None:
        self.assertEqual(htmltext.plaintext_to_html(""), "<p></p>")


class RenderBody(unittest.TestCase):
    def test_auto_renders_to_html(self) -> None:
        body, mime = htmltext.render_body("hi", "auto")
        self.assertEqual(mime, "text/html")
        self.assertIn("<p>hi</p>", body)

    def test_html_is_left_alone(self) -> None:
        body, mime = htmltext.render_body("<h1>x</h1>", "html")
        self.assertEqual((body, mime), ("<h1>x</h1>", "text/html"))

    def test_text_stays_plain(self) -> None:
        body, mime = htmltext.render_body("x < y", "text")
        self.assertEqual((body, mime), ("x < y", "text/plain"))


if __name__ == "__main__":
    unittest.main()
