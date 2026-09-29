# -*- coding: utf-8 -*-

from pathlib import Path
from datetime import datetime
import certifi
import tempfile
import json
import logging
import os
import sys
import getpass

from cryptography.hazmat.primitives import serialization


# =====================================================
# ログ作成
# =====================================================

def create_logger():
    """
    ログファイルとターミナルの両方へログを出力する。
    """

    base_dir = Path(__file__).resolve().parent

    log_file = base_dir / datetime.now().strftime(
        "box_snowflake_put_%Y_%m_%d_%H_%M_%S.log"
    )

    logger = logging.getLogger("snowflake_put")

    # ログ出力先の重複登録を防ぐ
    if logger.handlers:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)

    logger.setLevel(logging.INFO)

    # 上位Loggerへの伝播を止め、重複出力を防ぐ
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"
    )

    # ログファイルへの出力設定
    file_handler = logging.FileHandler(
        log_file,
        encoding="utf-8"
    )

    # ターミナルへの出力設定
    console_handler = logging.StreamHandler(
        sys.stdout
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger, log_file


# =====================================================
# config.json読込
# =====================================================

def load_config(config_file):
    """
    config.jsonからSnowflake接続情報を読み込む。
    """

    if not config_file.is_file():
        raise FileNotFoundError(
            f"config.jsonが存在しません: {config_file}"
        )

    try:
        with config_file.open(
            "r",
            encoding="utf-8-sig"
        ) as file:
            config = json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(
            "config.jsonのJSON形式が正しくありません。"
            f" 行={error.lineno},"
            f" 列={error.colno},"
            f" 内容={error.msg}"
        ) from error

    required_keys = [
    "user",
    "account",
    "warehouse",
    "database",
    "schema",
    "stage_name",
    "stage_path",
    "netskope_cert_path",
    "rsa_key_path",
    "target_folder",
    "target_file"
    ]

    missing_keys = [
        key
        for key in required_keys
        if not config.get(key)
    ]

    if missing_keys:
        raise ValueError(
            "config.jsonに必要な設定がありません: "
            + ", ".join(missing_keys)
        )

    return config


# =====================================================
# 証明書設定
# =====================================================

def configure_certificate(
    config,
    logger
):
    """
    certifiのCA Bundleと
    Netskope証明書を結合して利用する。
    """

    certifi_bundle = Path(
        certifi.where()
    )

    netskope_cert = Path(
        config["netskope_cert_path"]
    )

    logger.info(
        "certifi=%s",
        certifi_bundle
    )

    logger.info(
        "netskope=%s",
        netskope_cert
    )

    if not netskope_cert.is_file():
        raise FileNotFoundError(
            f"証明書ファイルが存在しません: "
            f"{netskope_cert}"
        )

    bundle_path = (
        Path(tempfile.gettempdir())
        / "snowflake_ca_bundle.pem"
    )

    with certifi_bundle.open(
        "r",
        encoding="utf-8"
    ) as certifi_file:

        with netskope_cert.open(
            "r",
            encoding="utf-8"
        ) as netskope_file:

            with bundle_path.open(
                "w",
                encoding="utf-8"
            ) as output_file:

                output_file.write(
                    certifi_file.read()
                )

                output_file.write("\n")

                output_file.write(
                    netskope_file.read()
                )

    os.environ[
        "REQUESTS_CA_BUNDLE"
    ] = str(bundle_path)

    os.environ[
        "SSL_CERT_FILE"
    ] = str(bundle_path)

    logger.info(
        "証明書設定完了=%s",
        bundle_path
    )



# =====================================================
# 秘密鍵読込
# =====================================================

def load_private_key(config, logger):
    """
    暗号化されたRSA秘密鍵を読み込み、
    Snowflake Connectorへ渡すDER形式へ変換する。
    """

    rsa_key_path = Path(config["rsa_key_path"])
    

    logger.info("秘密鍵=%s", rsa_key_path)

    if not rsa_key_path.is_file():
        raise FileNotFoundError(
            f"秘密鍵が存在しません: {rsa_key_path}"
        )

    passphrase = os.getenv(
        "SNOWFLAKE_KEY_PASSPHRASE"
    )

    if not passphrase:
        raise ValueError(
            "環境変数SNOWFLAKE_KEY_PASSPHRASEが"
            "設定されていません。"
        )

    logger.info("秘密鍵読込開始")

    try:
        with rsa_key_path.open("rb") as key_file:
            private_key = (
                serialization.load_pem_private_key(
                    key_file.read(),
                    password=passphrase.encode("utf-8")
                )
            )

    except (ValueError, TypeError) as error:
        raise ValueError(
            "秘密鍵を読み込めませんでした。"
            "秘密鍵ファイルまたはパスフレーズを"
            "確認してください。"
        ) from error

    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    logger.info("秘密鍵読込成功")

    return private_key_der

# =====================================================
# Box Driveファイル確認
# =====================================================

def get_target_file(config, logger):

    windows_user = getpass.getuser()

    logger.info(
        "Windowsログインユーザー=%s",
        windows_user
    )

    file_path = (
        #Boxまでのパスは固定
        Path(
            rf"C:\Users\{windows_user}\Box"
        )
        / Path(config["target_folder"])
        / config["target_file"]
    )

    allowed_extensions = [
        ".csv",
        ".xlsx"
    ]

    if not file_path.exists():
        raise FileNotFoundError(
            f"ファイルが存在しません: "
            f"{file_path}"
        )

    if file_path.suffix.lower() not in allowed_extensions:
        raise ValueError(
            "許可されていない拡張子です。"
        )

    return file_path


# =====================================================
# Snowflake接続
# =====================================================

def connect_snowflake(
    config,
    private_key_der,
    logger
):
    """
    キーペア認証でSnowflakeへ接続する。
    """

    # 証明書の環境変数設定後にimportする
    import snowflake.connector

    logger.info("Snowflake接続開始")
    logger.info("Snowflakeユーザー=%s", config["user"])
    logger.info("Snowflakeアカウント=%s", config["account"])
    logger.info("ウェアハウス=%s", config["warehouse"])
    logger.info("データベース=%s", config["database"])
    logger.info("スキーマ=%s", config["schema"])

    conn = snowflake.connector.connect(
        user=config["user"],
        account=config["account"],
        warehouse=config["warehouse"],
        database=config["database"],
        schema=config["schema"],
        private_key=private_key_der
    )

    logger.info("Snowflake接続成功")

    return conn


# =====================================================
# Snowflake接続確認
# =====================================================

def check_connection(conn, logger):
    """
    Snowflakeの現在の接続情報を取得してログへ出力する。
    """

    cur = None

    try:
        cur = conn.cursor()

        logger.info("接続確認SQL実行")

        cur.execute(
            """
            SELECT
                CURRENT_USER(),
                CURRENT_ROLE(),
                CURRENT_WAREHOUSE(),
                CURRENT_DATABASE(),
                CURRENT_SCHEMA()
            """
        )

        row = cur.fetchone()

        if row is None:
            raise RuntimeError(
                "接続確認SQLの結果を取得できませんでした。"
            )

        logger.info("接続確認成功")

    finally:
        if cur is not None:
            cur.close()
            logger.info("接続確認用カーソル切断完了")


# =====================================================
# PUT実行
# =====================================================

def put_file(
    conn,
    local_file,
    stage_name,
    stage_path,
    logger
):
    """
    Box Drive上のCSVファイルをSnowflake StageへPUTする。
    """

    # Windowsのバックスラッシュをスラッシュへ変換
    snowflake_path = local_file.as_posix()

    # SQL文字列内のシングルクォートをエスケープ
    snowflake_path = snowflake_path.replace(
        "'",
        "''"
    )


    put_sql = f"""
PUT 'file:///{snowflake_path}'
@{stage_name}/{stage_path}
AUTO_COMPRESS = TRUE
OVERWRITE = TRUE
"""

    logger.info("PUT SQL")
    logger.info("%s", put_sql.strip())

    cur = None

    try:
        cur = conn.cursor()

        logger.info("PUT開始")
        logger.info("アップロード元=%s", local_file)
        logger.info("アップロード先=@%s/%s", stage_name, stage_path)

        cur.execute(put_sql)

        columns = []

        if cur.description is not None:
            columns = [
                column[0]
                for column in cur.description
            ]

        rows = cur.fetchall()

        logger.info("PUT完了")
        logger.info("PUT結果件数=%s", len(rows))

        if not rows:
            logger.warning("PUT結果は0件です。")
            return

        for row_no, row in enumerate(
            rows,
            start=1
        ):
            logger.info(
                "===== PUT RESULT %s =====",
                row_no
            )

            if columns:
                for column_name, value in zip(
                    columns,
                    row
                ):
                    logger.info(
                        "%s=%s",
                        column_name,
                        value
                    )
            else:
                logger.info("%s", row)

    finally:
        if cur is not None:
            cur.close()
            logger.info("PUT用カーソル切断完了")


# =====================================================
# メイン処理
# =====================================================

def main():

    logger, log_file = create_logger()

    conn = None
    processing_succeeded = False

    logger.info(
        "================================"
    )
    logger.info("プログラム開始")
    logger.info(
        "================================"
    )

    logger.info("ログファイル=%s", log_file)

    try:
        base_dir = Path(__file__).resolve().parent

        # ---------------------------------
        # config.json読込
        # ---------------------------------

        config_file = base_dir / "config.json"

        logger.info("config.json読込開始")
        logger.info("config.json=%s", config_file)

        config = load_config(config_file)

        logger.info("config.json読込成功")
        logger.info(
            "アップロード先Stage=@%s/%s",
            config["stage_name"].lstrip("@"),
            config["stage_path"]
        )

        # ---------------------------------
        # 証明書設定
        # ---------------------------------

        configure_certificate(
            config,
            logger
        )

        # ---------------------------------
        # 秘密鍵読込
        # ---------------------------------

        private_key_der = load_private_key(
            config,
            logger
        )

        # ---------------------------------
        # Box DriveのCSV確認
        # ---------------------------------

        target_file = get_target_file(
            config,
            logger
        )

        # ---------------------------------
        # Snowflake接続
        # ---------------------------------

        conn = connect_snowflake(
            config=config,
            private_key_der=private_key_der,
            logger=logger
        )

        # ---------------------------------
        # Snowflake接続確認
        # ---------------------------------

        check_connection(
            conn,
            logger
        )

        # ---------------------------------
        # PUT
        # ---------------------------------

        put_file(
            conn=conn,
            local_file=target_file,
            stage_name=config["stage_name"],
            stage_path=config["stage_path"],
            logger=logger
        )

        processing_succeeded = True

        logger.info(
            "処理正常終了"
        )

    except Exception as error:
        # logger.exceptionは現在の例外と
        # Traceback全体をターミナルとログファイルへ出力する
        logger.exception(
            "処理失敗: エラー種別=%s, エラー内容=%s",
            type(error).__name__,
            str(error)
        )

        # PowerShell側にも異常終了を通知する
        raise

    finally:
        if conn is not None:
            try:
                conn.close()
                logger.info(
                    "Snowflake切断完了"
                )

            except Exception as close_error:
                # 元処理が失敗している場合に、切断エラーで
                # 元のエラーを上書きしない
                logger.exception(
                    "Snowflake切断失敗: %s",
                    str(close_error)
                )

        logger.info(
            "最終処理結果=%s",
            "成功" if processing_succeeded else "失敗"
        )

        logger.info(
            "ログファイル=%s",
            log_file
        )

        logger.info(
            "================================"
        )
        logger.info(
            "プログラム終了"
        )
        logger.info(
            "================================"
        )


if __name__ == "__main__":
    main()
