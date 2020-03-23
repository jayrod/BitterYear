import re
from argparse import ArgumentParser
from pathlib import Path

from markdown_table import Table


class Markdown:
    def render_md_table(self, columns: list, full_table: list) -> str:
        return Table(columns, full_table).render()

    def insert_md_table(
        self, markdown: str, md_table: str, replace_string: str
    ) -> None:
        """ Inserts a markdown table into a document at a given tag placement.

            Arguments:
                markdown(str): Path to markdown file
                md_table(str): Markdown table text to be inserted

            Exceptions:
                FileNotFounderror if markdown not found
        """

        content = open(markdown, "r").read(-1)

        # regex
        regex = r"\[\[\s?{0}\s?\]\]".format(replace_string)

        # if there exists a tag then substitute our data into it
        if re.findall(regex, content):
            content = re.sub(regex, md_table, content)
        else:
            content += md_table

        with open(markdown, "w") as m_file:
            m_file.write(content)

    def output(self, args: ArgumentParser, columns: list, table: list) -> None:

        if columns is None:
            raise ValueError("Columns is of NoneType")
        if table is None:
            raise ValueError("Table is of NoneType")

        # if Output file given then write output to it
        if args.markdown:
            md_table = self.render_md_table(columns, table)
            Markdown().insert_md_table(args.markdown, md_table, "SOLOSUNRISE")
