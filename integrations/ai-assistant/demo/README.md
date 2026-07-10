# Demo recording

`demo.sh` is a one-take terminal demo of the harness: OIDC login, turn-JWT
exchange, the read-allowed/write-denied ceiling with no AI involved, one real
question with its verifiability label, and one zero-hit honesty case. It only
needs the stack up and seeded first:

```bash
make keys wazuh securityconfig poc seed
./demo/demo.sh          # dry run it once before recording
```

Two ways to record it:

**GIF via VHS** (recommended for the README - deterministic and re-recordable):

```bash
go install github.com/charmbracelet/vhs@latest   # or: brew install vhs
vhs demo/demo.tape                               # writes demo/demo.gif
```

Adjust the two long `Sleep` values in `demo.tape` to your model's latency
(local models need more, lane 0 hits need almost none), then re-run `vhs`.
Embed it at the top of the main README:

```markdown
![Demo: one question through the harness, with its verifiability label](demo/demo.gif)
```

**Cast via asciinema** (lighter, plays in the browser):

```bash
asciinema rec -c ./demo/demo.sh demo.cast
asciinema upload demo.cast        # or: agg demo.cast demo/demo.gif
```

Keep the recording under a minute: the point is the verifiability label and
the 403, not the model's prose.
