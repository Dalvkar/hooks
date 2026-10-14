"""HOOK 2 (Codex) · PreToolUse + PermissionRequest (Bash)
Bloquea comandos peligrosos antes de que se ejecuten o se apruebe su escalación.
Ambos eventos reciben el comando en tool_input.command, pero cada uno requiere
una forma JSON de denegación diferente.
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

PELIGROSOS = {
    r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r": "borrado recursivo forzado (rm -rf)",
    r"Remove-Item\b.*-Recurse": "borrado recursivo en PowerShell",
    r"git\s+push\b.*(--force|-f\b)": "git push --force (reescribe la historia del equipo)",
    r"git\s+reset\s+--hard": "git reset --hard (pierde cambios sin confirmar)",
    r"DROP\s+(TABLE|DATABASE)": "eliminar tablas o bases de datos",
    r"\bdel\s+/[sq]": "borrado masivo en Windows",
}

datos = json.loads(sys.stdin.buffer.read().decode("utf-8"))
evento = datos.get("hook_event_name", "PreToolUse")
comando = datos.get("tool_input", {}).get("command", "")

for patron, motivo in PELIGROSOS.items():
    if re.search(patron, comando, re.IGNORECASE):
        razon = f"⛔ BLOQUEADO por hook: {motivo}. Comando: {comando}"

        if evento == "PermissionRequest":
            salida = {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {
                        "behavior": "deny",
                        "message": razon,
                    },
                }
            }
        else:
            salida = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": razon,
                }
            }

        print(json.dumps(salida, ensure_ascii=False))
        sys.exit(0)

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "hooks"))
from verificar_push import verificar_push

verificar_push(comando)
sys.exit(0)
