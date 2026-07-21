# Least-Privilege Dashboard Editing and Reporting (OpenSearch Security RBAC)

## Table of Contents
- [Introduction](#introduction)
- [Step 1: Grant Basic Dashboards Write Access](#step-1-grant-basic-dashboards-write-access)
- [Step 2: Grant Reporting-Plugin Cluster Permissions](#step-2-grant-reporting-plugin-cluster-permissions)
- [Step 3: Add Index Permissions on Reporting System Indices](#step-3-add-index-permissions-on-reporting-system-indices)
- [Step 4: Map Roles to Your Internal User](#step-4-map-roles-to-your-internal-user)
- [Step 5: Bootstrap the Reporting Plugin](#step-5-bootstrap-the-reporting-plugin)
- [References](#references)

## Introduction

A common requirement: operators should be able to **save and edit dashboards and Discover saved searches, and generate/download reports**, without being granted full administrative rights. This applies to any Wazuh deployment (self-hosted or cloud) since the dashboard's security layer is the OpenSearch Security plugin.

The recipe, using an example internal user named `reportuser`:

1. Assign the reserved **`kibana_user`** role so the user can create and modify dashboard objects (`.kibana*` indices).
2. Grant **Reporting-plugin cluster permissions** (or assign the reserved `reports_full_access` role).
3. Add **index permissions on the reporting system indices** (`.opendistro-reports-*`) so the plugin can read/write its own definitions and instances.
4. **Map all of these roles** to the internal user.
5. **Bootstrap the Reporting plugin** by logging in once as an admin to auto-create its system indices.

After completing these steps (and restarting the Wazuh dashboard with `run_as: true` and clearing the browser cache), the user can save/edit dashboards and generate/download reports while adhering to the principle of least privilege.

## Step 1: Grant Basic Dashboards Write Access

1. In the Wazuh dashboard UI, go to **Indexer Management > Security > Roles**.
2. Search for the reserved role **`kibana_user`** and open its details.
3. Under **Mapped users**, add **`reportuser`**, then click **Map**.

This role grants cluster-wide searches, index monitoring, and write access to the OpenSearch Dashboards indices -- enough to save and edit dashboards, visualizations, and saved searches without admin privileges.

## Step 2: Grant Reporting-Plugin Cluster Permissions

Either assign the reserved **`reports_full_access`** role, or add its equivalent cluster permissions to your custom role:

```yaml
cluster_permissions:
  - cluster:admin/opendistro/reports/definition/create
  - cluster:admin/opendistro/reports/definition/update
  - cluster:admin/opendistro/reports/definition/on_demand
  - cluster:admin/opendistro/reports/definition/delete
  - cluster:admin/opendistro/reports/definition/get
  - cluster:admin/opendistro/reports/definition/list
  - cluster:admin/opendistro/reports/instance/list
  - cluster:admin/opendistro/reports/instance/get
  - cluster:admin/opendistro/reports/menu/download
```

The reserved `reports_full_access` role already includes exactly these permissions.

## Step 3: Add Index Permissions on Reporting System Indices

By default, users -- even with the cluster rights above -- cannot read or write the Reporting plugin's system indices. To fix this without over-broad access:

1. In your custom role, scroll to **Index permissions**.
2. Click **Add** and enter:

   ```yaml
   index_patterns:
     - ".opendistro-reports-*"
   allowed_actions:
     - "system:admin/system_index"
   ```

3. Save the role.

This grants just enough rights on `.opendistro-reports-definitions` and `.opendistro-reports-instances` for listing, reading, and writing report definitions and instances -- and nothing else.

## Step 4: Map Roles to Your Internal User

Ensure **all** needed roles are mapped to the user:

1. Under **Indexer Management > Security > Roles**, open your custom role (e.g. `report_user`).
2. Under **Mapped users**, add **`reportuser`** and click **Map**.
3. Repeat for the reserved roles **`kibana_user`** and **`reports_full_access`** if you did not add their permissions to your custom role directly.

## Step 5: Bootstrap the Reporting Plugin

Perform a one-time initialization:

1. Log in as an **admin** (a user with `all_access`).
2. Navigate to **Dashboard Management > Reporting**.

Opening the Reporting UI auto-creates the two required system indices. After that, `reportuser` can view and manage reports without hitting an "Insufficient permissions" error.

## References

- [Wazuh RBAC - how to create and map internal users](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html)
- [OpenSearch Security - predefined roles](https://opensearch.org/docs/latest/security/access-control/users-roles/)
- [Wazuh Cloud service: credentials and API access](wazuh-cloud-service.md)
