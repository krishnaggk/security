/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;


public class NodesDnApiTest extends AbstractRestApiUnitTest {
	private HttpResponse response;

	private void testCrudScenarios(final int expectedStatus, final Header...headers) throws Exception {
		response = rh.executeGetRequest("_opendistro/_security/api/nodesdn", headers);
		Assert.assertEquals(expectedStatus, response.getStatusCode());
		if (expectedStatus == HttpStatus.SC_OK) {
			Assert.assertEquals("{\"connection1\":[\"cn=popeye\"]}", response.getBody());
		}

		response = rh.executeGetRequest("_opendistro/_security/api/nodesdn/connection1", headers);
		Assert.assertEquals(expectedStatus, response.getStatusCode());
		if (expectedStatus == HttpStatus.SC_OK) {
			Assert.assertEquals("{\"connection1\":[\"cn=popeye\"]}", response.getBody());
		}

		response = rh.executePutRequest("_opendistro/_security/api/nodesdn/connection1", "{\"nodes_dn\": [\"cn=popeye\"]}", headers);
		Assert.assertEquals(expectedStatus, response.getStatusCode());

		response = rh.executePatchRequest("/_opendistro/_security/api/nodesdn/connection1", "[{ \"op\": \"add\", \"path\": \"/nodes_dn/-\", \"value\": \"bluto\" }]", headers);
		Assert.assertEquals(expectedStatus, response.getStatusCode());

		response = rh.executePatchRequest("/_opendistro/_security/api/nodesdn", "[{ \"op\": \"remove\", \"path\": \"/connection1/nodes_dn/0\"}]", headers);
		Assert.assertEquals(expectedStatus, response.getStatusCode());

		response = rh.executeDeleteRequest("_opendistro/_security/api/nodesdn/connection1", headers);
		Assert.assertEquals(expectedStatus, response.getStatusCode());
	}

	@Test
	public void testNodesDnApiWithDynamicConfigDisabled() throws Exception {
		setup();
		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendAdminCertificate = true;

		testCrudScenarios(HttpStatus.SC_BAD_REQUEST);
	}

	@Test
	public void testNodesDnApi() throws Exception {
		Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, true).build();
		setupWithRestRoles(settings);

		final Header adminCredsHeader = encodeBasicHeader("admin", "admin");
		final Header nonAdminCredsHeader = encodeBasicHeader("sarek", "sarek");

		{
			// No creds, no admin certificate - UNAUTHORIZED
			rh.keystore = "restapi/kirk-keystore.jks";
			rh.sendAdminCertificate = false;
			testCrudScenarios(HttpStatus.SC_UNAUTHORIZED);
		}

		{
			// admin creds, no admin certificate - FORBIDDEN
			rh.keystore = "restapi/kirk-keystore.jks";
			rh.sendAdminCertificate = false;
			testCrudScenarios(HttpStatus.SC_FORBIDDEN, adminCredsHeader);
		}

		{
			// any creds, admin certificate - OK
			rh.keystore = "restapi/kirk-keystore.jks";
			rh.sendAdminCertificate = true;
			testCrudScenarios(HttpStatus.SC_OK, nonAdminCredsHeader);
		}
	}
}
