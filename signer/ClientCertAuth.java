import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509KeyManager;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.impl.client.HttpClients;

public class ClientCertAuth extends Thread implements X509KeyManager
{
	private static final String USER_AGENT = "Some Arbitrary User Agent";
	private static final String LOGIN_PAGE = "https://www.test.link/login.php";
	private X509KeyManager keyManager;
	private String alias;

	public ClientCertAuth() throws GeneralSecurityException, IOException
	{
		// Get KeyStore from smart card
		KeyStore keyStore = Utility.digitalSigner.loadKeyStorePKCS11();
		alias = Utility.digitalSigner.getAliasForAuth(keyStore);

		// Setup managers
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore, null);
		keyManager = (X509KeyManager) kmf.getKeyManagers()[0];

		// Request KeyStore from smart card
		SSLContext sslContext = SSLContexts.custom().loadKeyMaterial(keyStore, null).build();
		sslContext.init(new KeyManager[] { ClientCertAuth.this }, null, null);

		// Try to authenticate (without automatic redirect)
		HttpClient httpClient = HttpClients.custom().disableRedirectHandling().setUserAgent(USER_AGENT).setSSLContext(sslContext).build();
		HttpResponse response = httpClient.execute(new HttpGet(LOGIN_PAGE));
		
		// I hope this object returns the result I expect
		System.out.println(response);

		/*
		 * Here you have the "response" instance. You may do further steps to
		 * achieve full login (it may depend on the page).
		 *
		 * Check for response code. if (response.getStatusLine().getStatusCode()
		 * != HttpStatus.SC_MOVED_TEMPORARILY) continue;
		 * 
		 * Get session identifier to use in my pretty application. String
		 * loginToken =
		 * response.getLastHeader("Set-Cookie").getValue().replaceAll(
		 * "(JSESSIONID=)|;.{1,}", "").replace("\r", "").replace("\n", "");
		 * 
		 */
	}

	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
	{
		return alias;
	}

	public X509Certificate[] getCertificateChain(String alias)
	{
		return keyManager.getCertificateChain(alias);
	}

	@Override
	public String chooseServerAlias(String arg0, Principal[] arg1, Socket arg2)
	{
		return keyManager.chooseServerAlias(arg0, arg1, arg2);
	}

	@Override
	public String[] getClientAliases(String arg0, Principal[] arg1)
	{
		return keyManager.getClientAliases(arg0, arg1);
	}

	@Override
	public PrivateKey getPrivateKey(String arg0)
	{
		return keyManager.getPrivateKey(arg0);
	}

	@Override
	public String[] getServerAliases(String arg0, Principal[] arg1)
	{
		return keyManager.getServerAliases(arg0, arg1);
	}
}
