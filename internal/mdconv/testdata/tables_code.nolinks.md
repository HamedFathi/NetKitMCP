# Widget API

See the introduction, the changelog, this section, a next page and a fake link.

Inline `widget.New()` call.

## Endpoints

| Method | Path            | Description                  |
|--------|-----------------|------------------------------|
| GET    | `/widgets`      | List widgets                 |
| POST   | `/widgets`      | Create a widget \| with pipe |
| DELETE | `/widgets/{id}` | **Removes** a widget         |

## Examples

```go
package main

func main() {
	fmt.Println("hi <there>")
}
```

```python
def add(a, b):
    return a + b
```

```bash
curl -s https://api.example.com/widgets
```

```
no language here
```

## Errors

- ~~404~~ 410 when gone
- 429 when rate limited
