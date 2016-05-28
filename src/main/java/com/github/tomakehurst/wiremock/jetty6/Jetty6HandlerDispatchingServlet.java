/*
 * Copyright (C) 2011 Thomas Akehurst
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.tomakehurst.wiremock.jetty6;

import com.github.tomakehurst.wiremock.common.LocalNotifier;
import com.github.tomakehurst.wiremock.common.Notifier;
import com.github.tomakehurst.wiremock.core.WireMockApp;
import com.github.tomakehurst.wiremock.http.HttpHeader;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.RequestHandler;
import com.github.tomakehurst.wiremock.http.Response;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.github.tomakehurst.wiremock.http.RequestMethod.GET;
import static com.google.common.base.Charsets.UTF_8;
import static java.net.HttpURLConnection.HTTP_NOT_FOUND;
import static java.net.URLDecoder.decode;

public class Jetty6HandlerDispatchingServlet extends HttpServlet {

	public static final String SHOULD_FORWARD_TO_FILES_CONTEXT = "shouldForwardToFilesContext";
	public static final String MAPPED_UNDER_KEY = "mappedUnder";

	private static final long serialVersionUID = -6602042274260495538L;
	
	private RequestHandler requestHandler;
	private String mappedUnder;
	private Notifier notifier;
	private HttpRequestNotifierHelper notifierHelper;

	private String wiremockFileSourceRoot = "/";
	private boolean shouldForwardToFilesContext;
	
	@Override
	public void init(ServletConfig config) {
	    ServletContext context = config.getServletContext();
	    shouldForwardToFilesContext = getFileContextForwardingFlagFrom(config);
	    
	    if (context.getInitParameter("WireMockFileSourceRoot") != null) {
	        wiremockFileSourceRoot = context.getInitParameter("WireMockFileSourceRoot");
	    }
		
		String handlerClassName = config.getInitParameter(RequestHandler.HANDLER_CLASS_KEY);
		mappedUnder = getNormalizedMappedUnder(config);
		context.log(RequestHandler.HANDLER_CLASS_KEY + " from context returned " + handlerClassName +
			". Normlized mapped under returned '" + mappedUnder + "'");
		requestHandler = (RequestHandler) context.getAttribute(handlerClassName);
		notifier = (Notifier) context.getAttribute(Notifier.KEY);
		notifierHelper = new HttpRequestNotifierHelper();
	}
	
	/**
	 * @param config Servlet configuration to read
	 * @return Normalized mappedUnder attribute without trailing slash
	*/
	private String getNormalizedMappedUnder(ServletConfig config) {
		String mappedUnder = config.getInitParameter(MAPPED_UNDER_KEY);
		if(mappedUnder == null) {
			return null;
		}
		if (mappedUnder.endsWith("/")) {
			mappedUnder = mappedUnder.substring(0, mappedUnder.length() - 1);
		}
		return mappedUnder;
	}
	
	private boolean getFileContextForwardingFlagFrom(ServletConfig config) {
		String flagValue = config.getInitParameter(SHOULD_FORWARD_TO_FILES_CONTEXT);
		return Boolean.valueOf(flagValue);
	}

	@Override
	protected void service(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
		LocalNotifier.set(notifier);
		notifier.info(notifierHelper.log(httpServletRequest));

		Request request = new Jetty6HttpServletRequestAdapter(httpServletRequest, mappedUnder);
		Response response = requestHandler.handle(request);
        if (Thread.currentThread().isInterrupted()) {
            return;
        }
		if (response.wasConfigured()) {
		    applyResponse(response, httpServletResponse);
		} else if (request.getMethod().equals(GET) && shouldForwardToFilesContext) {
		    forwardToFilesContext(httpServletRequest, httpServletResponse, request);
		} else {
			httpServletResponse.sendError(HTTP_NOT_FOUND);
		}
	}

    public static void applyResponse(Response response, HttpServletResponse httpServletResponse) {
        if (response.getFault() != null) {
            response.getFault().apply(new Jetty6FaultInjector(httpServletResponse));
            return;
        }

        httpServletResponse.setStatus(response.getStatus());
        for (HttpHeader header: response.getHeaders().all()) {
            for (String value: header.values()) {
                httpServletResponse.addHeader(header.key(), value);
            }
        }

        writeAndTranslateExceptions(httpServletResponse, response.getBody());
    }

    private static void writeAndTranslateExceptions(HttpServletResponse httpServletResponse, byte[] content) {
        try {
            ServletOutputStream out = httpServletResponse.getOutputStream();
            out.write(content);
            out.flush();
            out.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void forwardToFilesContext(HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse, Request request) throws ServletException, IOException {
        String forwardUrl = wiremockFileSourceRoot + WireMockApp.FILES_ROOT + request.getUrl();
        RequestDispatcher dispatcher = httpServletRequest.getRequestDispatcher(decode(forwardUrl, UTF_8.name()));
        dispatcher.forward(httpServletRequest, httpServletResponse);
    }

	/**
	 * Helper to prepare log messages for {@link Jetty6HandlerDispatchingServlet}.
	 * It adds remote IP address for regular request#toString().
	 */
	private final class HttpRequestNotifierHelper {
		private final String HTTP_REQUEST_LOG_FORMAT =
				"Request received:\n" +     // just header
				"Remote Address:%s\n" +     // remote address IP
				"%s";                       // standard number of fields for
											// httpServletRequest#toString()

		String log(final HttpServletRequest request) {
			return String.format(HTTP_REQUEST_LOG_FORMAT, extractIpAddress(request), request);
		}

		/**
		 * Extract client IP address from request.
		 *
		 * This method handles also a case if user is behind a proxy server or
		 * access your web server through a load balancer (for example, in cloud
		 * hosting). Simple javax.servlet.ServletRequest#getRemoteAddr()
		 * will get the IP address of the proxy server or load balancer server,
		 * not the original IP address of a client.
		 * To solve we look at header <b>X-FORWARDED-FOR</b> first. See details
		 * <a href="https://en.wikipedia.org/wiki/X-Forwarded-For</a>
		 *
		 * @param request http request
		 * @return client IP address
		 */
		String extractIpAddress(final HttpServletRequest request) {
			// is client behind something?
			String ipAddress = request.getHeader("X-FORWARDED-FOR");
			if (ipAddress == null) {
				ipAddress = request.getRemoteAddr();
			}

			return ipAddress;
		}
	}
}
