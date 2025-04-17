import asyncio

import aioldap3


async def gssapi_example() -> None:
    conn = aioldap3.LDAPConnection(
        server=aioldap3.Server(host="ruslan.md.multifactor.dev", port=389),
        user="user@RUSLAN.MD.MULTIFACTOR.DEV",
        sasl_mechanism="GSSAPI",
    )

    await conn.bind(method="SASL")
    print(f"Whoami result = {await conn.whoami()}")


def main() -> None:
    asyncio.run(gssapi_example())


if __name__ == "__main__":
    main()
