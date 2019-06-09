package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

@SuppressWarnings("deprecation")
public class MyCode extends CodeV3
{
	private KeyStore localKeyStore;
	private final static String keyStorePath;
	private final static char[] keyStorePassword;

	private String[] SANGeneralNameChoice = { "otherName", "rfc822Name", "dNSName", "x400Address", "directoryName",
			"ediPartyName", "uniformResourceIdentifier", "iPAddress", "registeredID" };

	static
	{
		Security.addProvider(new BouncyCastleProvider());

		// hard-coded data
		keyStorePath = "zpKeyStore";
		keyStorePassword = "zastita_podataka".toCharArray();
	}

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException
	{
		super(algorithm_conf, extensions_conf, extensions_rules);
	}

	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name)
	{
		try
		{
			if (localKeyStore.getCertificate(keypair_name) == null)
				return null;

			X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			PublicKey pk = certificate.getPublicKey();

			return pk.getAlgorithm();
		}
		catch (KeyStoreException e)
		{
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getCertPublicKeyParameter(String keypair_name)
	{
		try
		{
			if (localKeyStore.getCertificate(keypair_name) == null)
				return null;

			X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			PublicKey pk = certificate.getPublicKey();

			if (pk instanceof RSAPublicKey)
				return String.valueOf(((RSAPublicKey) pk).getModulus().bitLength());
			else if (pk instanceof DSAPublicKey)
				return String.valueOf(((DSAPublicKey) pk).getY().bitLength());
			else
				return null;
		}
		catch (KeyStoreException e)
		{
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getSubjectInfo(String keypair_name)
	{
		try
		{
			if (localKeyStore.getCertificate(keypair_name) == null)
				return null;

			X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			X500Principal principal = certificate.getSubjectX500Principal();

			StringBuilder sb = new StringBuilder();
			sb.append(principal.getName());

			return sb.toString();
		}
		catch (KeyStoreException e)
		{
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public boolean importCAReply(String file, String keypair_name)
	{
		FileInputStream input = null;

		try
		{
			input = new FileInputStream(file);

			CMSSignedData signature = new CMSSignedData(input);
			Store<X509CertificateHolder> store = signature.getCertificates();
			Collection<X509CertificateHolder> certificateHolders = store.getMatches(null);
			X509Certificate[] chain = new X509Certificate[certificateHolders.size()];
			int i = 0;
			for (X509CertificateHolder holder : certificateHolders)
				chain[i++] = new JcaX509CertificateConverter().getCertificate(holder);

			PrivateKey pk = (PrivateKey) localKeyStore.getKey(keypair_name, keyStorePassword);
			localKeyStore.setKeyEntry(keypair_name, pk, keyStorePassword, chain);

			saveLocalKeyStore();

			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		return false;
	}

	/*
	 * Metoda za uvoz zahteva za potpis sertifikata
	 * 
	 * Poziva se klikom na Sign CSR
	 */
	@Override
	public String importCSR(String file)
	{
		FileInputStream input = null;

		try
		{
			FileReader pemReader =  new FileReader(file);
			PEMParser parser = new PEMParser(pemReader);
						
			PKCS10CertificationRequest csr = (PKCS10CertificationRequest)parser.readObject();
			currentCSR = csr;

			return csr.getSubject().toString();
		}
		catch (Exception ex)
		{
			ex.printStackTrace();
		}
		finally
		{
			if (input != null)
				try
				{
					input.close();
				}
				catch (IOException e)
				{
					e.printStackTrace();
				}
		}

		return null;
	}

	private PKCS10CertificationRequest currentCSR;

	@Override
	public boolean signCSR(String file, String keypair_name, String algorithm)
	{
		try
		{
			if (access.getVersion() != Constants.V3)
				return false;

			X500Name issuerName = new JcaX509CertificateHolder(
					(X509Certificate) localKeyStore.getCertificate(keypair_name)).getSubject();
			PublicKey csrPublicKey = new JcaPKCS10CertificationRequest(currentCSR).getPublicKey();
			X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName,
					new BigInteger(access.getSerialNumber()), access.getNotBefore(), access.getNotAfter(),
					currentCSR.getSubject(), csrPublicKey);

			// TODO: provera koji kljuc bi trebao
			AddExtensions(builder, csrPublicKey);

			ContentSigner signer = new JcaContentSignerBuilder(algorithm)
					.build((PrivateKey) localKeyStore.getKey(keypair_name, keyStorePassword));
			X509Certificate signedCertificate = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
			CMSSignedDataGenerator cmsSignerDataGenerator = new CMSSignedDataGenerator();

			List<JcaX509CertificateHolder> chain = new ArrayList<>();
			CMSTypedData cmsTypedData = new CMSProcessableByteArray(signedCertificate.getEncoded());
			chain.add(new JcaX509CertificateHolder(signedCertificate));
			for (Certificate cert : localKeyStore.getCertificateChain(keypair_name))
				chain.add(new JcaX509CertificateHolder((X509Certificate) cert));

			cmsSignerDataGenerator.addCertificates(new CollectionStore(chain));
			CMSSignedData cmsSignedData = cmsSignerDataGenerator.generate(cmsTypedData);

			OutputStream output = new FileOutputStream(file);
			output.write(cmsSignedData.getEncoded());
			output.close();

			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		return false;
	}

	/*
	 * Metoda za izvoz zahteva za potpis sertifikata
	 * 
	 * Poziva se klikom na Export CSR
	 */
	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm)
	{
		try
		{
			if (!localKeyStore.containsAlias(keypair_name) || !localKeyStore.isKeyEntry(keypair_name))
				return false;

			X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());

			PrivateKey privateKey = (PrivateKey) localKeyStore.getKey(keypair_name, keyStorePassword);
			PublicKey publicKey = certificate.getPublicKey();

			JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
					certificate.getSubjectX500Principal(), publicKey);
			List<ASN1ObjectIdentifier> extensions = holder.getExtensionOIDs();
			Iterator<ASN1ObjectIdentifier> it = extensions.iterator();
			while (it.hasNext())
			{
				ASN1ObjectIdentifier oid = it.next();
				csrBuilder.addAttribute(oid, holder.getExtension(oid));
			}

			ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(privateKey);
			PKCS10CertificationRequest csr = csrBuilder.build(signer);

			FileWriter output = new FileWriter(file);
			JcaPEMWriter pemWriter = new JcaPEMWriter(output);
			
			pemWriter.writeObject(csr);
			pemWriter.close();

			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public boolean canSign(String keypair_name)
	{
		try
		{
			if (!localKeyStore.containsAlias(keypair_name))
				return false;

			X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			int pathLength = certificate.getBasicConstraints();

			if (pathLength == -1)
				return false;
			else
				return true;
		}
		catch (KeyStoreException e)
		{
			e.printStackTrace();
		}

		return false;
	}

	/*
	 * Metoda za izvoz sertifikata iz lokalnog skladista kljuceva
	 * 
	 * Poziva se klikom na Export certificate
	 */
	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format)
	{
		FileOutputStream fos = null;

		try
		{

			if (format == Constants.HEAD) // izvoz Head only
			{
				Certificate certificate = localKeyStore.getCertificate(keypair_name);
				if (certificate == null)
					return false;

				if (format == Constants.DER) // DER -> binary encoded certificate
				{
					fos = new FileOutputStream(file);
					fos.write(certificate.getEncoded());
				}
				else // PEM -> Base64 encoded data with --Begin
				{
					OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(file));
					PemWriter pw = new PemWriter(osw);
					PemObject p = new PemObject("CERTIFICATE", certificate.getEncoded());
					pw.writeObject(p);
					pw.close();
					osw.close();
				}
			}
			else // izvoz Entire chain, mora da ide sa PEM
			{
				// TODO: da li je najdublji sertifikat ukljucen u Certificate[] niz
				// TODO: testiranje ovoga
				Certificate certificate = localKeyStore.getCertificate(keypair_name);
				Certificate[] certificates = localKeyStore.getCertificateChain(keypair_name);

				OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(file));
				JcaPEMWriter pw = new JcaPEMWriter(osw);
				//pw.writeObject(certificate);

				if (certificates != null)
				{
					for (Certificate cert : certificates)
					{
						pw.writeObject(cert);
						/*PemObject p = new PemObject("CERTIFICATE", cert.getEncoded());
						pw.writeObject(p);
						pw.newLine();*/
					}
				}
				
				pw.close();
				osw.close();
			}

			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			if (fos != null)
				try
				{
					fos.close();
				}
				catch (IOException e)
				{
					e.printStackTrace();
				}
		}

		return false;
	}

	/*
	 * Metoda za uvoz sertifikata u lokalno skladiste kljuceva
	 * 
	 * Poziva se klikom na Import certificate
	 */
	@Override
	public boolean importCertificate(String file, String keypair_name)
	{
		try
		{
			if (localKeyStore.containsAlias(keypair_name))
			{
				access.reportError("Certificate with the same name already exists.");
				return false;
			}

			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			FileInputStream fis = new FileInputStream(file);
			X509Certificate certificate = (X509Certificate) factory.generateCertificate(fis);

			localKeyStore.setCertificateEntry(keypair_name, certificate);
			saveLocalKeyStore();

			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		return false;
	}

	/*
	 * Metoda za izvoz p12 fajla iz sistema
	 * 
	 * Poziva se klikom na Export p12
	 */
	@Override
	public boolean exportKeypair(String keypair_name, String file, String password)
	{
		try
		{
			KeyStore export = KeyStore.getInstance("PKCS12");
			export.load(null, password.toCharArray());

			PrivateKey pk = (PrivateKey) localKeyStore.getKey(keypair_name, keyStorePassword);
			Certificate[] cc = localKeyStore.getCertificateChain(keypair_name);

			KeyStore.PrivateKeyEntry pke = new PrivateKeyEntry(pk, cc);
			KeyStore.PasswordProtection pp = new PasswordProtection(password.toCharArray());

			export.setEntry(keypair_name, pke, pp);

			FileOutputStream fos = new FileOutputStream(file);
			export.store(fos, password.toCharArray());
			fos.close();

			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		return false;
	}

	/*
	 * Metoda za uvozenje p12 fajla u sistem
	 * 
	 * Poziva se klikom na Import p12
	 */
	@Override
	public boolean importKeypair(String keypair_name, String file, String password)
	{
		FileInputStream fis = null;

		try
		{
			if (localKeyStore.containsAlias(keypair_name))
			{
				access.reportError("Key with the same name already exists.");
				return false;
			}

			fis = new FileInputStream(file);
			KeyStore remoteKeyStore = KeyStore.getInstance("pkcs12");
			remoteKeyStore.load(fis, password.toCharArray());

			Enumeration<String> aliases = remoteKeyStore.aliases();
			ArrayList<String> listOfAliases = Collections.list(aliases);
			int ID = 1;

			// TODO: da li trebamo da ucitamo sve kljuceve

			for (String name : listOfAliases)
			{
				PublicKey PUK = remoteKeyStore.getCertificate(name).getPublicKey();
				PrivateKey PRK = (PrivateKey) remoteKeyStore.getKey(name, password.toCharArray());

				KeyStore.PrivateKeyEntry pke = new KeyStore.PrivateKeyEntry(PRK,
						remoteKeyStore.getCertificateChain(name));
				KeyStore.PasswordProtection pp = new PasswordProtection(keyStorePassword);

				if (listOfAliases.size() == 1)
					localKeyStore.setEntry(keypair_name, pke, pp);
				else
				{
					String newName = keypair_name + String.valueOf(ID++);
					localKeyStore.setEntry(newName, pke, pp);
				}
			}

			saveLocalKeyStore();

			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			if (fis != null)
				try
				{
					fis.close();
				}
				catch (IOException e)
				{
					e.printStackTrace();
				}
		}

		return false;
	}

	/*
	 * Metode za ucitavanje informacija o kljucevima/sertifikatu i prikaz podataka o
	 * istom na grafickom interfejsu
	 */
	@Override
	public int loadKeypair(String keypair_name)
	{
		try
		{
			// vraca -1 ako je greska
			if (localKeyStore == null || !localKeyStore.containsAlias(keypair_name))
				return -1;

			X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);

			X500Principal subjectPrincipal = certificate.getSubjectX500Principal();
			X500Principal issuerPrincipal = certificate.getIssuerX500Principal();
			PublicKey publicKey = certificate.getPublicKey();

			// racunanje duzine kljuca
			String keySize;
			if (publicKey instanceof RSAPublicKey)
				keySize = String.valueOf(((RSAPublicKey) publicKey).getModulus().bitLength());
			else
			{
				access.reportError("Certificate algorithm not supported!");
				return -1;
			}

			// subject info group box
			access.setSubject(subjectPrincipal.getName());

			// ca info group box
			access.setIssuer(issuerPrincipal.getName());
			access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());

			// choose signature algorithm group box
			access.setPublicKeyAlgorithm("RSA");
			access.setPublicKeyDigestAlgorithm(certificate.getSigAlgName()); // combobox za hash funkciju
			access.setPublicKeyParameter(keySize); // combobox za duzinu kljuca

			// certificate version group box
			access.setVersion(certificate.getVersion() - 1);
			// certificate serial number group box
			access.setSerialNumber(String.valueOf(certificate.getSerialNumber()));
			// certificate validity group box
			access.setNotBefore(certificate.getNotBefore());
			access.setNotAfter(certificate.getNotAfter());

			/*
			 * if (certificate.getBasicConstraints() != -1) access.setCA(true); else
			 * access.setCA(false);
			 */

			// load extensions to GUI
			ExtractAuthorityKeyIdentifier(certificate);
			ExtractSubjectAlternativeNames(certificate);
			ExtractBasicConstraintsInfo(certificate);

			if (certificate.getBasicConstraints() != -1)
				return 2; // trusted certificate
			else if (certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()))
				return 0; // self signed
			else
				return 1; // signed
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		// greska inace
		return -1;
	}

	/*
	 * Metode za brisanje sadrzaja lokalnog skladista kljuceva i sertifikata koja se
	 * poziva se kada se pokrece aplikacija i pri azuriranje grafickog interfejsa
	 */
	@Override
	public Enumeration<String> loadLocalKeystore()
	{
		FileInputStream fis = null;
		FileOutputStream fos = null;

		try
		{
			// trazenje pkcs12 storage
			localKeyStore = KeyStore.getInstance("pkcs12");

			if (new File(keyStorePath).isFile())
			{
				// keystore postoji
				fis = new FileInputStream(keyStorePath);

				localKeyStore.load(fis, keyStorePassword);
			}
			else
			{
				// keystore ne postoji
				fos = new FileOutputStream(keyStorePath);

				// pravljenje novog i cuvanje
				localKeyStore.load(null, keyStorePassword);
				localKeyStore.store(fos, keyStorePassword);
			}

			// vracanje svih alijasa
			return localKeyStore.aliases();
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			try
			{
				// moze u isti try jer ce jedan uvek da bude null
				if (fis != null)
					fis.close();

				if (fos != null)
					fos.close();
			}
			catch (IOException e)
			{
				e.printStackTrace();
			}
		}

		return null;
	}

	/*
	 * Metode za ucitavanje sadrzaja lokalnog skladista kljuceva i sertifikata
	 * 
	 * Poziva se klikom na Reset Local KeyStore
	 */
	@Override
	public void resetLocalKeystore()
	{
		FileOutputStream fos = null;

		try
		{
			fos = new FileOutputStream(keyStorePath);

			KeyStore ks = KeyStore.getInstance("pkcs12");
			ks.load(null, keyStorePassword);
			ks.store(fos, keyStorePassword);

			localKeyStore = ks;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			try
			{
				if (fos != null)
					fos.close();
			}
			catch (IOException e)
			{
				e.printStackTrace();
			}
		}
	}

	/*
	 * Metode za brisanje izabranog kljuca/sertifikata iz liste
	 * 
	 * Poziva se klikom na Remove KeyPair
	 */
	@Override
	public boolean removeKeypair(String keypair_name)
	{
		try
		{
			if (localKeyStore.containsAlias(keypair_name))
			{
				localKeyStore.deleteEntry(keypair_name);
				saveLocalKeyStore();
				return true;
			}
		}
		catch (KeyStoreException e)
		{
			e.printStackTrace();
		}

		return false;
	}

	/*
	 * Metode za pravljenje i cuvanja novog sertifikata napravljenog na osnovu
	 * formulara
	 * 
	 * Poziva se klikom na Save
	 */
	@Override
	public boolean saveKeypair(String keypair_name)
	{
		try
		{
			// trebaju da budu podrzani samo RSA i verzija 3
			if (!access.getPublicKeyAlgorithm().equals("RSA"))
			{
				access.reportError("No other algorithm than RSA is supported.");
				return false;
			}
			else if (access.getVersion() != Constants.V3)
			{
				access.reportError("Only V3 certificates are supported.");
				return false;
			}
			else if (localKeyStore.containsAlias(keypair_name))
			{
				access.reportError("Keypair with the same name already exists.");
				return false;
			}

			// generisanje para kljuceva za RSA
			int keySize = Integer.parseInt(access.getPublicKeyParameter());
			KeyPair keyPair = GenerateRSAKeyPair(keySize);

			X500Name principal = GenerateX500Name();
			X509Certificate certificate = GenerateCertificate(keyPair, principal);

			KeyStore.Entry pke = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[] { certificate });
			KeyStore.PasswordProtection pp = new PasswordProtection(keyStorePassword);
			localKeyStore.setEntry(keypair_name, pke, pp);
			saveLocalKeyStore();

			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		return false;
	}

	///////////////////////////////////////////////
	/////////////// PRIVATE METHODS ///////////////
	///////////////////////////////////////////////

	private KeyPair GenerateRSAKeyPair(int length)
	{
		try
		{
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(length, new SecureRandom());

			return generator.generateKeyPair();
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}

		return null;
	}

	private X500Name GenerateX500Name()
	{
		StringBuilder sb = new StringBuilder();

		String cn = access.getSubjectCommonName();
		String ou = access.getSubjectOrganizationUnit();
		String o = access.getSubjectOrganization();
		String l = access.getSubjectLocality();
		String s = access.getSubjectState();
		String c = access.getSubjectCountry();

		if (!cn.equals(""))
			sb.append("CN=" + cn + ",");
		if (!ou.equals(""))
			sb.append("OU=" + ou + ",");
		if (!o.equals(""))
			sb.append("O=" + o + ",");
		if (!l.equals(""))
			sb.append("L=" + l + ",");
		if (!s.equals(""))
			sb.append("ST=" + s + ",");
		if (!c.equals(""))
			sb.append("C=" + c + ",");

		if (sb.length() > 0)
			sb.deleteCharAt(sb.length() - 1);

		return new X500Name(sb.toString());
	}

	private X509Certificate GenerateCertificate(KeyPair keyPair, X500Name name) throws Exception
	{
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name,
				new BigInteger(access.getSerialNumber()), access.getNotBefore(), access.getNotAfter(), name,
				keyPair.getPublic());

		AddExtensions(builder, keyPair.getPublic());

		ContentSigner signer = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm())
				.build(keyPair.getPrivate());
		return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
	}

	private void AddExtensions(X509v3CertificateBuilder generator, PublicKey AKIPublicKey) throws Exception
	{
		// TODO: da li ekstenzija moze da bude kriticna ako ne postoji sadrzaj iste

		AuthorityKeyIdentifier aki = null;
		if (access.getEnabledAuthorityKeyID())
		{
			JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
			aki = extensionUtils.createAuthorityKeyIdentifier(AKIPublicKey, new X500Principal(access.getSubject()),
					new BigInteger(access.getSerialNumber()));

			generator.addExtension(Extension.authorityKeyIdentifier, access.isCritical(Constants.AKID), aki);
		}

		/////////////////////////////////////////////////////////////////////
		String[] alternativeNames = access.getAlternativeName(Constants.SAN);
		if (alternativeNames.length > 0)
		{
			ASN1Encodable[] arr = new ASN1Encodable[alternativeNames.length];
			for (int i = 0; i < alternativeNames.length; i++)
			{
				String add = alternativeNames[i].toString();
				String id = add.substring(0, add.indexOf('=')).trim();
				String value = add.substring(add.indexOf("=") + 1, add.length()).trim();

				if (id.equals("otherName"))
					arr[i] = new GeneralName(GeneralName.otherName, value);
				else if (id.equals("rfc822Name"))
					arr[i] = new GeneralName(GeneralName.rfc822Name, value);
				else if (id.equals("dNSName"))
					arr[i] = new GeneralName(GeneralName.dNSName, value);
				else if (id.equals("x400Address"))
					arr[i] = new GeneralName(GeneralName.x400Address, value);
				else if (id.equals("directoryName"))
					arr[i] = new GeneralName(GeneralName.directoryName, value);
				else if (id.equals("ediPartyName"))
					arr[i] = new GeneralName(GeneralName.ediPartyName, value);
				else if (id.equals("uniformResourceIdentifier"))
					arr[i] = new GeneralName(GeneralName.uniformResourceIdentifier, value);
				else if (id.equals("iPAddress"))
					arr[i] = new GeneralName(GeneralName.iPAddress, value);
				else if (id.equals("registeredID"))
					arr[i] = new GeneralName(GeneralName.registeredID, value);
				else
				{
					access.reportError("SAN tag not recognized.");
					throw new Exception("SAN tag not recognized.");
				}
			}

			DERSequence subjectAlternativeNames = new DERSequence(arr);
			generator.addExtension(X509Extensions.SubjectAlternativeName, access.isCritical(Constants.SAN),
					subjectAlternativeNames);
		}
		///////////////////////////////////////////////////////////////////////
		BasicConstraints bc;
		if (access.isCA())
		{
			try
			{
				int parsed = Integer.parseInt(access.getPathLen());
				bc = new BasicConstraints(parsed);
			}
			catch (Exception ex)
			{
				bc = new BasicConstraints(Integer.MAX_VALUE);
			}
		}
		else
			bc = new BasicConstraints(false);

		generator.addExtension(Extension.basicConstraints, access.isCritical(Constants.BC), bc);
	}

	private void saveLocalKeyStore()
	{
		FileOutputStream fos = null;

		try
		{
			fos = new FileOutputStream(keyStorePath);
			localKeyStore.store(fos, keyStorePassword);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			try
			{
				if (fos != null)
					fos.close();
			}
			catch (IOException e)
			{
				e.printStackTrace();
			}
		}
	}

	private void ExtractBasicConstraintsInfo(X509Certificate certificate)
	{
		int bc = certificate.getBasicConstraints();

		access.setCritical(Constants.BC,
				certificate.getCriticalExtensionOIDs().contains(Extension.basicConstraints.getId()));

		access.setCA(bc != -1);
		if (bc != -1)
			access.setPathLen(String.valueOf(bc)); // vraca MAX_INT ako ne postoji maksimalan broj ulancavanja
	}

	private void ExtractSubjectAlternativeNames(X509Certificate certificate)
	{
		try
		{
			StringBuilder sb = new StringBuilder();

			access.setCritical(Constants.SAN,
					certificate.getCriticalExtensionOIDs().contains(Extension.subjectAlternativeName.getId()));

			Collection<List<?>> SAN = certificate.getSubjectAlternativeNames();

			if (SAN != null)
			{
				for (List<?> name : certificate.getSubjectAlternativeNames())
				{
					int generalName = (int) name.get(0);

					if (generalName < 0 || generalName >= SANGeneralNameChoice.length - 1)
					{
						access.reportError("SAN extension general name not supported!");
						return;
					}

					sb.append(SANGeneralNameChoice[generalName]);
					sb.append("=");
					sb.append(name.get(1));
					sb.append(", ");
				}

				if (sb.length() > 0)
					sb.setLength(sb.length() - 2);

				access.setAlternativeName(Constants.SAN, sb.toString());
			}
		}
		catch (CertificateParsingException e)
		{
			e.printStackTrace();
		}
	}

	private void ExtractAuthorityKeyIdentifier(X509Certificate certificate)
	{
		// TODO: testiranje ExtractAuthorityKeyIdentifier
		byte[] value = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());

		access.setCritical(Constants.AKID,
				certificate.getCriticalExtensionOIDs().contains(Extension.authorityKeyIdentifier.getId()));

		if (value != null)
		{
			byte[] octets = ASN1OctetString.getInstance(value).getOctets();
			AuthorityKeyIdentifier AKI = AuthorityKeyIdentifier.getInstance(octets);

			// TODO: testiranje implicitnih kastovanja
			if (AKI.getKeyIdentifier() != null)
				access.setAuthorityKeyID(new String(Hex.encode(AKI.getKeyIdentifier())));
			if (AKI.getAuthorityCertIssuer() != null)
				if (AKI.getAuthorityCertIssuer().getNames().length > 0)
					access.setAuthorityIssuer(AKI.getAuthorityCertIssuer().getNames()[0].toString());
			if (AKI.getAuthorityCertSerialNumber() != null)
				access.setAuthoritySerialNumber(AKI.getAuthorityCertSerialNumber().toString());

			access.setEnabledAuthorityKeyID(true);
		}
	}
}