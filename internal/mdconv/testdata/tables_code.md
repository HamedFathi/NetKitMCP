# Widget API

See the [introduction](https://example.com/docs/guide/intro.html), the [changelog](https://example.com/changelog), this [section](https://example.com/docs/api/widgets.html#errors), a [next page](https://example.com/docs/api/widgets.html?page=2) and a fake link.

![Architecture diagram](https://example.com/docs/api/img/diagram.png) Inline `widget.New()` call.

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
