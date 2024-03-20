=======
aioldap3
=======

Fork of repository: https://github.com/terrycain/aioldap

Documentation


Example
-------

Simple example of using aioboto3 to put items into a dynamodb table

.. code-block:: python

    conn = aioldap.LDAPConnection(Server(host='localhost', port=389))
    await conn.bind(
        bind_dn='admin',
        bind_pw='password,
    )

    print(await conn.whoami())

    dn = user_entry('modify', ldap_params['test_ou1'])
    await conn.add(
        dn=dn,
        object_class='inetOrgPerson',
        attributes={
            'description': 'some desc',
            'cn': 'some_user',
            'sn': 'some user',
            'employeeType': ['type1', 'type2']}
    )

    await conn.modify(
        dn=dn,
        changes={
            'sn': [('MODIFY_REPLACE', 'some other user')],
            'employeeType': [
                ('MODIFY_ADD', 'type3'),
                ('MODIFY_DELETE', 'type1'),
            ]
        }
    )

    # Now search for user
    async for user in conn.search(dn, search_filter='(uid=*)', search_scope='BASE', attributes='*'):
        assert user['dn'] == dn


Credits
-------

All of the credit goes to @cannatag who literally had done all of the hard work for me.
