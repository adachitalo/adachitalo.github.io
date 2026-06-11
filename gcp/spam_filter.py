"""LINE QR コード詐欺メールのフィルタ。

talo@talo.co.jp 宛に頻発する「LINEで業務連絡を統一するのでQRコードを返信してください」
系の詐欺メールを検出するための純粋関数。GCP の転送スクリプトに組み込んで、
True を返したメールは Gmail に転送せずに退避（GCS等）+ログで運用する想定。

組み込み例（Cloud Functions / Cloud Run Functions / Cloud Run など共通）:

    from spam_filter import is_spam_line_qr

    def forward_handler(raw_message):
        subject = get_header(raw_message, "Subject")
        sender  = get_header(raw_message, "From")
        body    = extract_text_body(raw_message)

        if is_spam_line_qr(subject, body, sender):
            archive_to_gcs(raw_message)          # 誤検知の救出用
            log.warning("spam_dropped",
                        extra={"from": sender, "subject": subject})
            return                                # ← Gmail に転送しない

        forward_to_gmail(raw_message)

判定方針（誤検知抑制のため AND 条件で絞る）:
  1. 件名 or 本文に LINE/ライン
  2. 件名 or 本文に QRコード/友だち追加/招待リンク
  3. 件名 or 本文に 返信/送付 などの依頼
  4. 送信元が信頼ドメインではない
  5. かつ（送信元がフリーメール or 強いスパムシグナルが本文に1つ以上）

検出パターンは Gmail 受信箱の実サンプル 50+ 件（2025〜2026 年）から抽出。
新パターンが来たら SPAM_SIGNALS / TRUSTED_SENDER_PATTERNS を調整する。
"""

from __future__ import annotations
import re

_FULLWIDTH_MAP = str.maketrans(
    {chr(c): chr(c - 0xFEE0) for c in range(0xFF01, 0xFF5F)} | {"　": " "}
)


def _normalize(text: str) -> str:
    """全角→半角、連続空白→単一空白、小文字化。"""
    if not text:
        return ""
    text = text.translate(_FULLWIDTH_MAP)
    text = re.sub(r"\s+", " ", text)
    return text.lower()


# "L I N E" "Ｌ Ｉ Ｎ Ｅ" のスペース挿入回避にも対応
LINE_RE = re.compile(r"l\s*i\s*n\s*e|ライン", re.IGNORECASE)
QR_RE = re.compile(
    r"q\s*r\s*コード|q\s*r\s*code|友だち追加|招待リンク|招待用リンク",
    re.IGNORECASE,
)
REPLY_REQ_RE = re.compile(
    r"ご返信|返信|送付|送ってくださ|お送り|ご提出|提出|共有",
)

FREE_MAIL_RE = re.compile(
    r"@(outlook|hotmail|yahoo|gmail|aol|live|msn|gmx|icloud|"
    r"qq|163|126|sohu|sina)\.",
    re.IGNORECASE,
)

# 実サンプルで頻出した強いスパム指標
SPAM_SIGNALS = [
    re.compile(r"お疲れ様です"),
    re.compile(r"順次\s*追加|順次\s*line"),
    re.compile(r"個人\s*line|個人\s*ライン"),
    re.compile(r"携帯電話を紛失|新しい\s*line\s*アカウント"),
    re.compile(r"業務連絡.{0,20}効率"),
    re.compile(r"line\s*グループ.{0,15}作成|新たに\s*line\s*グループ"),
    re.compile(r"連絡.{0,5}(統一|円滑)"),
    re.compile(r"緊急時の連絡|緊急\s*の\s*業務連絡"),
    re.compile(r"line\s*情報"),
]

# 信頼できる送信元（除外）。運用に合わせて追加していく。
TRUSTED_SENDER_PATTERNS = [
    re.compile(r"@talo\.co\.jp\b", re.IGNORECASE),          # 自社
    re.compile(r"@worksmobile\.com\b", re.IGNORECASE),       # LINE WORKS 公式
    re.compile(r"@google\.com\b", re.IGNORECASE),
    re.compile(r"@line\.me\b", re.IGNORECASE),
    re.compile(r"@linecorp\.com\b", re.IGNORECASE),
]


def is_spam_line_qr(subject: str, body: str, sender: str) -> bool:
    """LINE QR コード詐欺と判定したら True（=転送せず捨てるべき）。"""
    sender_norm = (sender or "").strip().lower()

    if any(p.search(sender_norm) for p in TRUSTED_SENDER_PATTERNS):
        return False

    text = _normalize(f"{subject or ''}\n{body or ''}")

    if not (LINE_RE.search(text) and QR_RE.search(text) and REPLY_REQ_RE.search(text)):
        return False

    from_free_mail = bool(FREE_MAIL_RE.search(sender_norm))
    signal_hits = sum(1 for p in SPAM_SIGNALS if p.search(text))

    return from_free_mail or signal_hits >= 1


if __name__ == "__main__":
    # 実サンプルからの抜粋。スニペットが短いケースも含む。
    SPAM_CASES = [
        ("株式会社タロハウス",
         "お疲れ様です。今後の連絡をLINEで統一するため、お手数ですが本メール受信後にQRコードをご返信ください。確認後、順次追加いたします。",
         "LiskaSchantini9093@outlook.com"),
        ("L I N E での業務連絡準備について",
         "業務連絡用 LINE 登録のお願いです。お手数ですが、自分の LINE QR コードを返信ください。情報は連絡目的のみ使用します。確認後、順次追加します。",
         "KemfortBarricelli48@outlook.com"),
        ("代表取締役社長：山口太郎",
         "お疲れ様です。携帯電話を紛失してしまい、現在LINEにログインできません。新しいLINEアカウントから改めて連絡しますので、お手数ですが、友だち追加用のQRコード（または招待リンク）を返信で送ってください。",
         "GraceEstrada7899@outlook.com"),
        ("株式会社ｔａｌｏ",
         "お疲れ様です。本メール受信後、今後の業務連絡の効率化を目的として、ご自身の個人LINEのQRコードを本メールアドレス宛にご返信いただきますようお願いいたします。",
         "SharonVang1409@outlook.com"),
        ("株式会社タロハウス",
         "本日は緊急の業務連絡がございますので、新たにLINEグループを作成いただけますでしょうか。作成が完了しましたら、グループのQRコードまたは招待リンクを本メール宛に返信いただけますでしょうか。",
         "JoshuaCook7380@outlook.com"),
        (" 山口太郎",
         "業務連絡や緊急時の連絡をスムーズに行うため、皆様のLINE情報を確認させてください。お手数ですが、LINEのQRコードまたはLINEリンクを本メールに返信してご提出いただけますでしょうか。",
         "MonteithHayley21@outlook.com"),
        ("株式会社タロ?インターナショナル",
         "業務上の都合により、貴方様の LINE QR コードが必要となりました。お手数ですが、本メールへ返信する形で LINE の QR コードを送付していただけますでしょうか。",
         "kfzlwmawksn@outlook.com"),
        ("安達博俊",  # 送信元が見慣れない法人ドメインだがフリーメールではないケース。補強シグナル多数で検出されるべき。
         "お疲れ様です。本メール受信後、今後の業務連絡の効率化を目的として、ご自身の個人LINEのQRコードを本メールアドレス宛にご返信いただきますようお願いいたします。",
         "h4-saiyo@h-4.jp"),
    ]

    HAM_CASES = [
        ("Re: 大西邸追加依頼",
         "追加で送っていただきたいCADデータがあります。軸組図など。宜しくお願い致します。",
         "yaeko-nakamura@shuwa-juken.co.jp"),
        ("ここが変わったLINE WORKS！2023年メジャーアップデート総まとめ",
         "本メールはLINE WORKSフリープランを登録いただいている方へお送りしています。",
         "dl_lineworksnews@worksmobile.com"),
        ("LINE WORKSアカウント変更のお知らせ",
         "外部トーク連携機能をご利用の場合は、「QRコード」「トークID」「招待用リンク」も変更となります。",
         "no_reply@worksmobile.com"),
        ("社内 LINE グループの件",
         "明日の打合せで LINE QR の取り扱いについて議論したいです。返信お待ちしています。",
         "k.nakatsubo@talo.co.jp"),
        ("お見積もりの件",
         "お見積もり書を添付します。ご確認の上、ご返信ください。",
         "mito@kimurakobo.com"),
    ]

    fails = 0
    print("=== SPAM (expected True) ===")
    for subj, body, sndr in SPAM_CASES:
        got = is_spam_line_qr(subj, body, sndr)
        print(f"  {got}  | {sndr} | {subj}")
        if not got:
            fails += 1
    print("\n=== HAM (expected False) ===")
    for subj, body, sndr in HAM_CASES:
        got = is_spam_line_qr(subj, body, sndr)
        print(f"  {got}  | {sndr} | {subj}")
        if got:
            fails += 1

    if fails:
        raise SystemExit(f"\n{fails} case(s) failed")
    print("\nAll cases passed.")
