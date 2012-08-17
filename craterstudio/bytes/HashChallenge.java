/*
 * Created on 26 mei 2009
 */

package craterstudio.bytes;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

public abstract class HashChallenge {
	public static HashChallenge forMD5() {
		return new HashChallenge() {
			@Override
			public byte[] hash(byte[] data) {
				return Hash.md5(data);
			}
		};
	}

	public static HashChallenge forSHA1() {
		return new HashChallenge() {
			@Override
			public byte[] hash(byte[] data) {
				return Hash.sha1(data);
			}
		};
	}

	public static HashChallenge forSHA256() {
		return new HashChallenge() {
			@Override
			public byte[] hash(byte[] data) {
				return Hash.sha256(data);
			}
		};
	}

	public abstract byte[] hash(byte[] data);

	public byte[] pass(byte[] user) {
		throw new UnsupportedOperationException();
	}

	private static final SecureRandom SALT_GEN = new SecureRandom();

	public byte[] salt() {
		// default implementation
		byte[] salt = new byte[256];
		SALT_GEN.nextBytes(salt);
		return salt;
	}

	private static final byte[] colon = new byte[] { (byte) ':' };

	public static boolean shake(HashChallenge c, byte[] user, byte[] pass, InputStream is, OutputStream os) throws IOException {
		DataInputStream dis = new DataInputStream(is);
		DataOutputStream dos = new DataOutputStream(os);

		dos.writeInt(user.length);
		dos.write(user);
		dos.flush();

		byte[] salthash = new byte[dis.readInt()];
		dis.readFully(salthash);

		byte[] joint = join(salthash, colon, pass, colon, user);
		Arrays.fill(pass, (byte) 0);
		byte[] answer = c.hash(joint);
		Arrays.fill(joint, (byte) 0);

		dos.write(answer);
		dos.flush();

		return dis.readBoolean();
	}

	/**
	 * @return user or <code>null</code>
	 */

	public static byte[] verify(HashChallenge c, InputStream is, OutputStream os) throws IOException {
		DataInputStream dis = new DataInputStream(is);
		DataOutputStream dos = new DataOutputStream(os);

		byte[] user = new byte[dis.readInt()];
		dis.readFully(user);

		byte[] salt = c.salt();
		byte[] salthash = c.hash(salt);
		Arrays.fill(salt, (byte) 0);

		dos.writeInt(salthash.length);
		dos.write(salthash);
		dos.flush();

		byte[] pass = c.pass(user);
		byte[] correctAnswer;

		if (pass == null) {
			correctAnswer = null;
		} else {
			byte[] joint = join(salthash, colon, pass, colon, user);
			Arrays.fill(pass, (byte) 0);
			correctAnswer = c.hash(joint);
			Arrays.fill(joint, (byte) 0);
		}

		byte[] receivedAnswer = new byte[salthash.length];
		dis.readFully(receivedAnswer);

		if (correctAnswer == null || !Arrays.equals(correctAnswer, receivedAnswer)) {
			dos.writeBoolean(false);
			dos.flush();
			return null;
		}
		dos.writeBoolean(true);
		dos.flush();
		return user;
	}

	private static byte[] join(byte[]... data) {
		int len = 0;
		for (byte[] d : data) {
			len += d.length;
		}

		byte[] c = new byte[len];
		int off = 0;
		for (byte[] d : data) {
			System.arraycopy(d, 0, c, off, d.length);
			off += d.length;
		}
		return c;
	}
}