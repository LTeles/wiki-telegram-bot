import os
import requests

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")

if not TOKEN:
    raise RuntimeError("A variável TELEGRAM_BOT_TOKEN não foi configurada.")

API_URL = f"https://api.telegram.org/bot{TOKEN}"


def get_updates():
    response = requests.get(
        f"{API_URL}/getUpdates",
        timeout=30
    )
    response.raise_for_status()
    return response.json()


def send_message(chat_id, text):
    response = requests.post(
        f"{API_URL}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": text
        },
        timeout=30
    )
    response.raise_for_status()


def main():
    print("Bot iniciado.")

    last_update_id = None

    while True:
        params = {
            "timeout": 30
        }

        if last_update_id is not None:
            params["offset"] = last_update_id + 1

        response = requests.get(
            f"{API_URL}/getUpdates",
            params=params,
            timeout=35
        )

        response.raise_for_status()
        data = response.json()

        for update in data.get("result", []):
            last_update_id = update["update_id"]

            message = update.get("message")
            if not message:
                continue

            chat_id = message["chat"]["id"]
            text = message.get("text", "")

            if text == "/start":
                send_message(
                    chat_id,
                    "Olá! 👋\n\n"
                    "Estou conectado ao Telegram.\n"
                    "Em breve vou acompanhar as edições da Wikipédia em tempo real."
                )


if __name__ == "__main__":
    main()
