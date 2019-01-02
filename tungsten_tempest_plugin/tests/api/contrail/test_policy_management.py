"""Tempest Suite for Policy Management of Contrail."""
# Copyright 2018 AT&T Corp
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from patrole_tempest_plugin import rbac_rule_validation
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.decorators import idempotent_id

from tungsten_tempest_plugin.tests.api.contrail import rbac_base

CONF = config.CONF


class PolicyManagementTest(rbac_base.BaseContrailTest):
    """Class to test the Policy Management of  Contrail."""

    @classmethod
    def skip_checks(cls):
        """Skip the Suite if the Contrail version is less than five."""
        super(PolicyManagementTest, cls).skip_checks()
        if float(CONF.sdn.contrail_version) < 5:
            msg = "policy_management requires Contrail >= 5"
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        """Create Policy Management to use across the Suite."""
        super(PolicyManagementTest, cls).resource_setup()
        cls.policy_management_uuid = cls._create_policy_management()

    @classmethod
    def _create_policy_management(cls):
        """Create a Policy Management."""
        fq_name = data_utils.rand_name('policy-management')
        post_body = {
            'parent_type': 'project',
            'fq_name': ["default-domain", cls.tenant_name, fq_name]
        }
        resp_body = cls.contrail_client.create_policy_management(
            **post_body)
        policy_management_uuid = resp_body['policy-management']['uuid']
        cls.addClassResourceCleanup(
            cls._try_delete_resource,
            cls.contrail_client.delete_policy_management,
            policy_management_uuid)
        return policy_management_uuid

    @rbac_rule_validation.action(service="Contrail",
                                 rules=["create_policy_management"])
    @idempotent_id('f6a208e1-f307-11e8-b6f7-0c4de9c6e8e3')
    def test_create_policy_management(self):
        """Create policy_management.

        RBAC test for the Contrail create_policy_management policy
        """
        with self.rbac_utils.override_role(self):
            self._create_policy_management()

    @rbac_rule_validation.action(service="Contrail",
                                 rules=["list_policy_management"])
    @idempotent_id('2984e8ae-f30a-11e8-870e-0c4de9c6e8e3')
    def test_list_policy_managements(self):
        """List policy_managements.

        RBAC test for the Contrail list_policy_managements policy
        """
        with self.rbac_utils.override_role(self):
            self.contrail_client.list_policy_managements()

    @rbac_rule_validation.action(service="Contrail",
                                 rules=["show_policy_management"])
    @idempotent_id('3ef2a168-f30a-11e8-ad60-0c4de9c6e8e3')
    def test_show_policy_management(self):
        """Show policy_management.

        RBAC test for the Contrail show_policy_management policy
        """
        with self.rbac_utils.override_role(self):
            self.contrail_client.\
                show_policy_management(self.policy_management_uuid)

    @rbac_rule_validation.action(service="Contrail",
                                 rules=["delete_policy_management"])
    @idempotent_id('5db9fe66-f30a-11e8-aba3-0c4de9c6e8e3')
    def test_delete_policy_management(self):
        """Delete policy_management.

        RBAC test for the Contrail delete_policy_management policy
        """
        obj_uuid = self._create_policy_management()
        with self.rbac_utils.override_role(self):
            self.contrail_client.\
                delete_policy_management(obj_uuid)

    @rbac_rule_validation.action(service="Contrail",
                                 rules=["update_service_object"])
    @idempotent_id('6b4e686e-f30a-11e8-81cb-0c4de9c6e8e3')
    def test_update_policy_management(self):
        """Update policy_management.

        RBAC test for the Contrail update_policy_management policy
        """
        put_body = {
            'display_name': data_utils.rand_name(
                'update_policy_management')}
        with self.rbac_utils.override_role(self):
            self.contrail_client.update_policy_management(
                self.policy_management_uuid, **put_body)
