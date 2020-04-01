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
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

public class SslConfigApiTest extends AbstractRestApiUnitTest {

	@Test
	public void testSecurityConfigApiRead() throws Exception {

		setup();

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendAdminCertificate = true;

		HttpResponse response = rh.executeGetRequest("/_opendistro/_security/api/ssl/config");
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		response = rh.executePutRequest("/_opendistro/_security/api/ssl/config/nodes_dn", "{\"xxx\": 1}");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePostRequest("/_opendistro/_security/api/ssl/config", "{\"xxx\": 1}");
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
        
        response = rh.executePatchRequest("/_opendistro/_security/api/ssl/config", "{\"xxx\": 1}");
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
        
        response = rh.executeDeleteRequest("/_opendistro/_security/api/ssl/config");
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
        
	}

	@Test
    public void testContained() throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true).build();
        setup(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;


        HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/securityconfig/config",
            FileHelper.loadFile( "restapi/securityconfig_op.json"));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        printConfig("Before");

        patch("other");
        printConfig("After 1");

        patch("other-2");
        printConfig("After 2");

        patch("other-2");
        printConfig("After 3");
    }

    private void patch(String value) throws Exception {
        HttpResponse response = rh.executePatchRequest(
            "/_opendistro/_security/api/securityconfig",
            String.format("[{\"op\": \"add\",\"path\": \"/config/dynamic/nodes_dn/%s\",\"value\": \"%s\"}]",
                value, value));
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    private void printConfig(String helper) throws Exception {
        HttpResponse response = rh.executeGetRequest("/_opendistro/_security/api/securityconfig");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        final String toPrint = String.format("GK [%s] -> %s", helper, response.getBody());
        System.out.println(toPrint);
    }
	
	@Test
	public void testSecurityConfigApiWrite() throws Exception {

	    Settings settings = Settings
            .builder()
            .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ALLOW_SSLCONFIG_MODIFICATION, true)
            .build();
        setupWithRestRoles(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;

        final String validConfig = FileHelper.loadFile("restapi/sslconfig.json");
        final String invalidConfig = FileHelper.loadFile("restapi/sslconfig_invalid.json");
        final Header credsHeader = encodeBasicHeader("test", "test");

        HttpResponse response;
        response = rh.executeGetRequest("/_opendistro/_security/api/ssl/config", credsHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePutRequest("/_opendistro/_security/api/ssl/config/xxx", validConfig, credsHeader);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executePutRequest("/_opendistro/_security/api/ssl/config/0", validConfig, credsHeader);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        rh.sendAdminCertificate = true;
        response = rh.executePutRequest("/_opendistro/_security/api/ssl/config/0", validConfig, credsHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        
        response = rh.executePutRequest("/_opendistro/_security/api/ssl/config/0", invalidConfig);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        response = rh.executeGetRequest("/_opendistro/_security/api/ssl/config");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePostRequest("/_opendistro/_security/api/ssl/config/0", "{\"xxx\": 1}");
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());


        response = rh.executeDeleteRequest("/_opendistro/_security/ssl/config");
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        response = rh.executeDeleteRequest("/_opendistro/_security/ssl/config/0");
        Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

    }

    @Test
    public void testPatch() throws Exception {
        Settings settings = Settings
            .builder()
            .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ALLOW_SSLCONFIG_MODIFICATION, true)
            .build();
        setupWithRestRoles(settings);

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = false;

        HttpResponse response;
        response = rh.executePatchRequest("/_opendistro/_security/api/ssl/config",
            "[{\"op\": \"add\",\"path\": \"/0\",\"value\": {\"nodes_dn\": {\"conn1\":[\"other\"]}}}]");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        response = rh.executePatchRequest("/_opendistro/_security/api/ssl/config",
            "[{\"op\": \"add\",\"path\": \"/0/nodes_dn\",\"value\": {\"conn1\":[\"other\"]}}]");
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        final Header credsHeader = encodeBasicHeader("test", "test");

        response = rh.executePatchRequest("/_opendistro/_security/api/ssl/config",
            "[{\"op\": \"add\",\"path\": \"/0\",\"value\": {\"nodes_dn\": {\"conn1\":[\"other\"]}}}]", credsHeader);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executePatchRequest("/_opendistro/_security/api/ssl/config",
            "[{\"op\": \"add\",\"path\": \"/0/nodes_dn\",\"value\": {\"conn1\":[\"other\"]}}]", credsHeader);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        rh.sendAdminCertificate = true;
        response = rh.executePatchRequest("/_opendistro/_security/api/ssl/config",
            "[{\"op\": \"add\",\"path\": \"/0\",\"value\": {\"nodes_dn\": {\"conn1\":[\"other\"]}}}]", credsHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePatchRequest("/_opendistro/_security/api/ssl/config",
            "[{\"op\": \"add\",\"path\": \"/0/nodes_dn\",\"value\": {\"conn1\":[\"other\"]}}]", credsHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        response = rh.executePatchRequest("/_opendistro/_security/api/ssl/config",
            "[{\"op\": \"add\",\"path\": \"/0/nodes_dn\",\"value\": {\"conn1\":\"other\"}}]", credsHeader);
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());

    }
}
