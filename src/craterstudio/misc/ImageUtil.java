/*
 * Created on 29 apr 2008
 */

package craterstudio.misc;

import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.Transparency;
import java.awt.image.BufferedImage;
import java.awt.image.DataBuffer;
import java.awt.image.DataBufferByte;
import java.awt.image.DataBufferInt;
import java.awt.image.IndexColorModel;
import java.awt.image.WritableRaster;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Iterator;
import java.util.List;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageReadParam;
import javax.imageio.ImageReader;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.FileImageInputStream;
import javax.imageio.stream.FileImageOutputStream;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.stream.ImageOutputStreamImpl;

import craterstudio.io.FileUtil;
import craterstudio.io.PrimIO;
import craterstudio.math.EasyMath;

import org.w3c.dom.Node;

import javax.imageio.*;
import javax.imageio.metadata.*;
import javax.imageio.stream.ImageOutputStream;

public class ImageUtil {

	public static void multiply(BufferedImage a, BufferedImage b, BufferedImage d) {
		if (a.getWidth() != b.getWidth() || a.getWidth() != d.getWidth())
			throw new IllegalStateException();
		if (a.getHeight() != b.getHeight() || a.getHeight() != d.getHeight())
			throw new IllegalStateException();

		int[] ai = ImageUtil.accessRasterIntArray(a);
		int[] bi = ImageUtil.accessRasterIntArray(b);
		int[] di = ImageUtil.accessRasterIntArray(d);

		if (ai.length != bi.length || ai.length != di.length)
			throw new IllegalStateException();

		for (int i = 0; i < ai.length; i++) {
			int a0 = ((ai[i] >> (3 * 8)) & 0xFF) * ((bi[i] >> (3 * 8)) & 0xFF) >> 8;
			int r0 = ((ai[i] >> (2 * 8)) & 0xFF) * ((bi[i] >> (2 * 8)) & 0xFF) >> 8;
			int g0 = ((ai[i] >> (1 * 8)) & 0xFF) * ((bi[i] >> (1 * 8)) & 0xFF) >> 8;
			int b0 = ((ai[i] >> (0 * 8)) & 0xFF) * ((bi[i] >> (0 * 8)) & 0xFF) >> 8;
			di[i] = (a0 << 24) | (r0 << 16) | (g0 << 8) | (b0 << 0);
		}
	}

	public static BufferedImage readImage(byte[] data) {
		ByteArrayInputStream bais = new ByteArrayInputStream(data);

		try {
			return ImageIO.read(bais);
		} catch (Exception exc) {
			ImageType type = getImageType(data);

			if (type == ImageType.TGA) {
				try {
					return readTGA(bais, bais.available());
				} catch (Exception exc2) {
					throw new IllegalStateException(exc2);
				}
			}

			throw new IllegalStateException("failed to read image: " + type, exc);
		}
	}

	public static BufferedImage gaussianBlur(BufferedImage img, int radius) {
		int w = img.getWidth();
		int h = img.getHeight();

		BufferedImage srcImg = new BufferedImage(img.getWidth(), img.getHeight(), BufferedImage.TYPE_INT_RGB);
		srcImg.getGraphics().drawImage(img, 0, 0, null);
		BufferedImage dstImg = new BufferedImage(img.getWidth(), img.getHeight(), BufferedImage.TYPE_INT_RGB);

		int[] src = accessRasterIntArray(srcImg);
		int[] dst = accessRasterIntArray(dstImg);

		int dim = radius * 2 + 1;
		float[] table = new float[dim * dim];
		float sum = 0.0f;
		for (int i = 0; i < table.length; i++) {
			int x = (i % dim) - radius;
			int y = (i / dim) - radius;
			float d = (float) Math.sqrt(x * x + y * y);
			d = EasyMath.interpolateWithCap(d, 0, radius, 1.0f, 0.0f);
			sum += (table[i] = d);
		}
		for (int i = 0; i < table.length; i++)
			table[i] /= sum;

		float[] r = new float[dst.length];
		float[] g = new float[dst.length];
		float[] b = new float[dst.length];

		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				for (int i = 0; i < table.length; i++) {
					int x0 = EasyMath.clamp(x + (i % dim) - radius, 0, w - 1);
					int y0 = EasyMath.clamp(y + (i / dim) - radius, 0, h - 1);
					int srcPixel = src[y0 * w + x0];
					r[y * w + x] += ((srcPixel >> 16) & 0xFF) * table[i];
					g[y * w + x] += ((srcPixel >> 8) & 0xFF) * table[i];
					b[y * w + x] += ((srcPixel >> 0) & 0xFF) * table[i];
				}
			}
		}

		for (int i = 0; i < dst.length; i++) {
			dst[i] = (((int) r[i]) << 16) | (((int) g[i]) << 8) | (((int) b[i]) << 0);
		}

		dstImg.setRGB(0, 0, w, h, dst, 0, w);

		return dstImg;
	}

	public static void blur(BufferedImage src, BufferedImage tmp, BufferedImage dst, int radius) {
		int[] srcArray = accessRasterIntArray(src);
		int[] tmpArray = accessRasterIntArray(tmp);
		int[] dstArray = accessRasterIntArray(dst);

		for (int i = 0; i < 2; i++) {
			blurScanlines(i == 0 ? srcArray : dstArray, src.getWidth(), radius, tmpArray);
			transpose(tmpArray, src.getWidth(), dstArray);
		}
	}

	public static BufferedImage blur(BufferedImage img, int radius) {
		BufferedImage srcImg = new BufferedImage(img.getWidth(), img.getHeight(), BufferedImage.TYPE_INT_RGB);
		srcImg.getGraphics().drawImage(img, 0, 0, null);
		BufferedImage dstImg = new BufferedImage(img.getWidth(), img.getHeight(), BufferedImage.TYPE_INT_RGB);

		int[] src = accessRasterIntArray(srcImg);
		int[] dst = accessRasterIntArray(dstImg);

		blurScanlines(src, img.getWidth(), radius, dst);
		transpose(dst, img.getWidth(), src);
		blurScanlines(src, img.getWidth(), radius, dst);
		transpose(dst, img.getWidth(), src);

		dstImg.setRGB(0, 0, img.getWidth(), img.getWidth(), src, 0, img.getWidth());

		return dstImg;
	}

	private static void transpose(int[] src, int width, int[] dst) {
		final int lines = src.length / width;

		for (int y = 0; y < lines; y++) {
			for (int x = 0; x < width; x++) {
				dst[x * width + y] = src[y * lines + x];
			}
		}
	}

	private static void blurScanlines(int[] src, int width, int radius, int[] dst) {
		final int lines = src.length / width;
		final int w_1 = width - 1;

		for (int y = 0; y < lines; y++) {
			int sumR = 0;
			int sumG = 0;
			int sumB = 0;
			int sumC = 0;

			for (int x = -radius; x < width; x++) {
				final int xAdd = x + radius;
				final int xSub = x - radius;

				if (EasyMath.isBetween(xAdd, 0, w_1)) {
					int pixel = src[y * width + xAdd];
					sumR += (pixel & 0xFF0000) >> 16;
					sumG += (pixel & 0x00FF00) >> 8;
					sumB += (pixel & 0x0000FF) >> 0;
					sumC += 1;
				}

				if (EasyMath.isBetween(x, 0, w_1)) {
					int curR = sumR / sumC;
					int curG = sumG / sumC;
					int curB = sumB / sumC;
					dst[y * width + x] = (curR << 16) | (curG << 8) | (curB << 0);
				}

				if (EasyMath.isBetween(xSub, 0, w_1)) {
					int pixel = src[y * width + xSub];
					sumR -= (pixel & 0xFF0000) >> 16;
					sumG -= (pixel & 0x00FF00) >> 8;
					sumB -= (pixel & 0x0000FF) >> 0;
					sumC -= 1;
				}
			}
		}
	}

	@SuppressWarnings("unused")
	private static void blurScanlinesSlow(int[] src, int width, int radius, int[] dst) {
		final int lines = src.length / width;

		for (int y = 0; y < lines; y++) {
			for (int x = 0; x < width; x++) {
				int sumR = 0;
				int sumG = 0;
				int sumB = 0;

				int pixelsOff = EasyMath.clamp(x - radius, 0, width - 1);
				int pixelsEnd = EasyMath.clamp(x + radius, 0, width - 1);

				for (int i = pixelsOff; i <= pixelsEnd; i++) {
					sumR += (src[y * width + i] & 0xFF0000) >> 16;
					sumG += (src[y * width + i] & 0x00FF00) >> 8;
					sumB += (src[y * width + i] & 0x0000FF) >> 0;
				}

				sumR /= pixelsEnd - pixelsOff + 1;
				sumG /= pixelsEnd - pixelsOff + 1;
				sumB /= pixelsEnd - pixelsOff + 1;

				dst[y * width + x] = (sumR << 16) | (sumG << 8) | (sumB << 0);
			}
		}
	}

	public static BufferedImage readTGA(File file) throws IOException {
		if (!file.exists()) {
			throw new FileNotFoundException(file.getAbsolutePath());
		}

		try {
			return readTGA(new FileInputStream(file), file.length());
		} catch (Exception exc) {
			throw new IOException(file.getAbsolutePath(), exc);
		}
	}

	public static BufferedImage readTGA(byte[] data) {
		try {
			return readTGA(new ByteArrayInputStream(data), data.length);
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		}
	}

	public static BufferedImage readTGA(InputStream is, long streamLength) throws IOException {
		if (streamLength < 18) {
			throw new IllegalStateException("not big enough to contain TGA header: " + streamLength);
		}

		DataInputStream dis = new DataInputStream(is);
		byte[] header = new byte[18];

		byte[] data = new byte[(int) (streamLength - header.length)];

		dis.read(header);
		dis.read(data);
		dis.close();

		if ((header[0] | header[1]) != 0)
			throw new IllegalStateException();

		boolean isRLE;

		if (header[2] == 2) {
			isRLE = false;
		} else if (header[2] == 10) {
			isRLE = true;
		} else {
			throw new IllegalStateException("header[2]=" + header[2]);
		}

		int w = 0, h = 0;
		w |= (header[12] & 0xFF) << 0;
		w |= (header[13] & 0xFF) << 8;
		h |= (header[14] & 0xFF) << 0;
		h |= (header[15] & 0xFF) << 8;

		boolean alpha;
		{
			if (isRLE) {
				alpha = false;
			} else {
				if ((w * h) * 3 == data.length)
					alpha = false;
				else if ((w * h) * 4 == data.length)
					alpha = true;
				else
					throw new IllegalStateException();
			}

			if (!alpha && (header[16] != 24))
				throw new IllegalStateException();
			if (alpha && (header[16] != 32))
				throw new IllegalStateException();
			if ((header[17] & 15) != (alpha ? 8 : 0))
				throw new IllegalStateException();
		}

		BufferedImage dst = new BufferedImage(w, h, alpha ? BufferedImage.TYPE_INT_ARGB : BufferedImage.TYPE_INT_RGB);
		int[] pixels = accessRasterIntArray(dst);
		if (pixels.length != w * h)
			throw new IllegalStateException();

		if (isRLE) {
			int p = 0;
			for (int i = 0; i < pixels.length;) {
				int packetID = data[p++] & 0xFF;
				int repeat = (packetID & 0x7F) + 1;

				if (packetID >> 7 == 0) {
					// no encoding, just N pixels
					for (int n = 0; n < repeat; n++) {
						pixels[i] |= ((data[p + 0]) & 0xFF) << 0;
						pixels[i] |= ((data[p + 1]) & 0xFF) << 8;
						pixels[i] |= ((data[p + 2]) & 0xFF) << 16;
						p += 3;
						i++;
					}
				} else {
					// repeat pixels N times
					int pixel = 0;
					pixel |= ((data[p + 0]) & 0xFF) << 0;
					pixel |= ((data[p + 1]) & 0xFF) << 8;
					pixel |= ((data[p + 2]) & 0xFF) << 16;
					p += 3;

					for (int n = 0; n < repeat; n++) {
						pixels[i++] = pixel;
					}
				}
			}
		} else {
			if (data.length != pixels.length * (alpha ? 4 : 3))
				throw new IllegalStateException();
			if (alpha) {
				for (int i = 0, p = (pixels.length - 1) * 4; i < pixels.length; i++, p -= 4) {
					pixels[i] |= ((data[p + 0]) & 0xFF) << 0;
					pixels[i] |= ((data[p + 1]) & 0xFF) << 8;
					pixels[i] |= ((data[p + 2]) & 0xFF) << 16;
					pixels[i] |= ((data[p + 3]) & 0xFF) << 24;
				}
			} else {
				for (int i = 0, p = (pixels.length - 1) * 3; i < pixels.length; i++, p -= 3) {
					pixels[i] |= ((data[p + 0]) & 0xFF) << 0;
					pixels[i] |= ((data[p + 1]) & 0xFF) << 8;
					pixels[i] |= ((data[p + 2]) & 0xFF) << 16;
				}
			}
		}

		if ((header[17] >> 4) == 1) {
			// ok
		} else if ((header[17] >> 4) == 0) {
			// flip horizontally

			for (int y = 0; y < h; y++) {
				int w2 = w / 2;
				for (int x = 0; x < w2; x++) {
					int a = (y * w) + x;
					int b = (y * w) + (w - 1 - x);
					int t = pixels[a];
					pixels[a] = pixels[b];
					pixels[b] = t;
				}
			}
		} else {
			// throw new UnsupportedOperationException("header[17]=" + header[17]);
		}

		return dst;
	}

	public static void writeTGA(BufferedImage src, File file) throws IOException {
		DataBuffer buffer = src.getRaster().getDataBuffer();
		boolean alpha = src.getColorModel().hasAlpha();
		byte[] data;

		if (buffer instanceof DataBufferByte) {
			byte[] pixels = ((DataBufferByte) src.getRaster().getDataBuffer()).getData();
			if (pixels.length != src.getWidth() * src.getHeight() * (alpha ? 4 : 3))
				throw new IllegalStateException();

			data = new byte[pixels.length];

			for (int i = 0, p = pixels.length - 1; i < data.length; i++, p--) {
				data[i] = pixels[p];
			}
		} else if (buffer instanceof DataBufferInt) {
			int[] pixels = accessRasterIntArray(src);
			if (pixels.length != src.getWidth() * src.getHeight())
				throw new IllegalStateException();

			data = new byte[pixels.length * (alpha ? 4 : 3)];

			if (alpha) {
				for (int i = 0, p = pixels.length - 1; i < data.length; i += 4, p--) {
					data[i + 0] = (byte) ((pixels[p] >> 0) & 0xFF);
					data[i + 1] = (byte) ((pixels[p] >> 8) & 0xFF);
					data[i + 2] = (byte) ((pixels[p] >> 16) & 0xFF);
					data[i + 3] = (byte) ((pixels[p] >> 24) & 0xFF);
				}
			} else {
				for (int i = 0, p = pixels.length - 1; i < data.length; i += 3, p--) {
					data[i + 0] = (byte) ((pixels[p] >> 0) & 0xFF);
					data[i + 1] = (byte) ((pixels[p] >> 8) & 0xFF);
					data[i + 2] = (byte) ((pixels[p] >> 16) & 0xFF);
				}
			}
		} else {
			throw new UnsupportedOperationException();
		}

		byte[] header = new byte[18];
		header[2] = 2; // uncompressed, true-color image
		header[12] = (byte) ((src.getWidth() >> 0) & 0xFF);
		header[13] = (byte) ((src.getWidth() >> 8) & 0xFF);
		header[14] = (byte) ((src.getHeight() >> 0) & 0xFF);
		header[15] = (byte) ((src.getHeight() >> 8) & 0xFF);
		header[16] = (byte) (alpha ? 32 : 24); // bits per pixel
		header[17] = (byte) ((alpha ? 8 : 0) | (1 << 4));

		RandomAccessFile raf = new RandomAccessFile(file, "rw");
		raf.write(header);
		raf.write(data);
		raf.setLength(raf.getFilePointer()); // trim
		raf.close();
	}

	public static BufferedImage mipmapGammaCorrected(BufferedImage src, int level) {
		if (level < 1) {
			throw new IllegalArgumentException();
		}

		for (int i = 0; i < level; i++) {
			BufferedImage tmp = mipmapGammaCorrected(src);
			if (i != 0)
				src.flush(); // do not flush argument
			src = tmp;
		}
		return src;
	}

	public static BufferedImage mipmapGammaCorrected(BufferedImage src) {
		int wSrc = src.getWidth();
		int hSrc = src.getHeight();

		if (wSrc % 2 != 0 || hSrc % 2 != 0) {
			throw new IllegalStateException("dimensions must be multiple of 2");
		}

		int wDst = wSrc / 2;
		int hDst = hSrc / 2;

		int[] argbFull = src.getRGB(0, 0, wSrc, hSrc, null, 0, wSrc);

		int type = BufferedImage.TYPE_INT_RGB;
		if (src.getAlphaRaster() != null) {
			type = BufferedImage.TYPE_INT_ARGB;

			// merge alpha into RGB values
			int[] alphaFull = src.getAlphaRaster().getPixels(0, 0, wSrc, hSrc, (int[]) null);
			for (int i = 0; i < alphaFull.length; i++) {
				argbFull[i] = (alphaFull[i] << 24) | (argbFull[i] & 0x00FFFFFF);
			}
		}

		BufferedImage half = new BufferedImage(wDst, hDst, type);

		int[] argbHalf = new int[argbFull.length >>> 2];

		for (int y = 0; y < hDst; y++) {
			for (int x = 0; x < wDst; x++) {
				int p0 = argbFull[((y << 1) | 0) * wSrc + ((x << 1) | 0)];
				int p1 = argbFull[((y << 1) | 1) * wSrc + ((x << 1) | 0)];
				int p2 = argbFull[((y << 1) | 1) * wSrc + ((x << 1) | 1)];
				int p3 = argbFull[((y << 1) | 0) * wSrc + ((x << 1) | 1)];

				int a = gammaCorrectedAverage(p0, p1, p2, p3, 24);
				int r = gammaCorrectedAverage(p0, p1, p2, p3, 16);
				int g = gammaCorrectedAverage(p0, p1, p2, p3, 8);
				int b = gammaCorrectedAverage(p0, p1, p2, p3, 0);

				argbHalf[y * wDst + x] = (a << 24) | (r << 16) | (g << 8) | (b << 0);
			}
		}

		half.setRGB(0, 0, wDst, hDst, argbHalf, 0, wDst);
		if (type == BufferedImage.TYPE_INT_ARGB) {
			// extract alpha from ARGB values
			int[] alpha = new int[argbHalf.length];
			for (int i = 0; i < alpha.length; i++)
				alpha[i] = (argbHalf[i] >> 24) & 0xFF;
			half.getAlphaRaster().setPixels(0, 0, wDst, hDst, alpha);
		}

		return half;
	}

	static int gammaCorrectedAverage(int a, int b, int c, int d, int shift) {
		float x = ((a >> shift) & 0xFF) / 255.0f;
		float y = ((b >> shift) & 0xFF) / 255.0f;
		float z = ((c >> shift) & 0xFF) / 255.0f;
		float w = ((d >> shift) & 0xFF) / 255.0f;

		float e = x * x + y * y + z * z + w * w;
		e = (float) Math.sqrt(e * 0.25f);
		return (int) (e * 255.0f);
	}

	//

	public static Dimension scaleSizeToArea(Dimension input, int area) {
		double w = input.getWidth();
		double h = input.getHeight();

		for (double f = 0.900; f < 1.000; f += 0.001) {
			while ((w * f * h * f) >= area) {
				w *= f;
				h *= f;
			}
		}

		return new Dimension((int) w, (int) h);
	}

	//

	public static byte[] writePNG(BufferedImage img) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		writePNG(img, baos);
		return baos.toByteArray();
	}

	public static void writePNG(BufferedImage img, OutputStream out) {
		try {
			ImageIO.write(img, "PNG", out);
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		}
	}

	public static void writePNG(BufferedImage img, File out) {
		FileUtil.writeFile(out, writePNG(img));
	}

	public static byte[] writeJPG(BufferedImage img, float quality) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			writeJPG(img, baos, quality);
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		}
		return baos.toByteArray();
	}

	private static ImageOutputStreamImpl createJpegIOS(final OutputStream out) {
		return new ImageOutputStreamImpl() {

			@Override
			public int read(byte[] b, int off, int len) throws IOException {
				throw new UnsupportedOperationException();
			}

			@Override
			public int read() throws IOException {
				throw new UnsupportedOperationException();
			}

			@Override
			public void write(byte[] buf, int off, int len) throws IOException {
				out.write(buf, off, len);
			}

			@Override
			public void write(int b) throws IOException {
				out.write(b);
			}

			@Override
			public void flush() throws IOException {
				super.flush();

				out.flush();
			}

			@Override
			public void close() throws IOException {
				super.close();

				out.close();
			}
		};
	}

	public static void writeJPG(BufferedImage img, OutputStream out, float quality) throws IOException {
		writeJPG(img, createJpegIOS(out), quality);
	}

	public static void writeJPG(BufferedImage img, File file, float quality) throws IOException {
		writeJPG(img, new FileImageOutputStream(file), quality);
	}

	private static void writeJPG(BufferedImage img, ImageOutputStreamImpl output, float quality) throws IOException {
		Iterator<ImageWriter> iter = ImageIO.getImageWritersByFormatName("jpeg");
		ImageWriter writer = iter.next();
		ImageWriteParam iwp = writer.getDefaultWriteParam();
		iwp.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
		iwp.setCompressionQuality(quality);

		writer.setOutput(output);
		IIOImage image = new IIOImage(img, null, null);
		writer.write(null, image, iwp);
		writer.dispose();
		output.close();
	}

	public static interface ImageRegionHandler {
		public void onRegion(Rectangle rect, BufferedImage img);
	}

	public static void readImageRegions(File file, Rectangle[] rects, ImageRegionHandler handler) throws IOException {
		ImageReader ir = ImageIO.getImageReadersByFormatName("jpeg").next();
		ImageInputStream iis = new FileImageInputStream(file);
		ir.setInput(iis);

		for (Rectangle rect : rects) {
			ImageReadParam irp = new ImageReadParam();
			irp.setSourceRegion(rect);
			handler.onRegion(rect, ir.read(0, irp));
		}
	}

	public static void makeTransparent(BufferedImage img) {
		Graphics2D g = img.createGraphics();
		g.setComposite(AlphaComposite.getInstance(AlphaComposite.CLEAR, 0.0f));
		g.fillRect(0, 0, img.getWidth(), img.getHeight());
		g.dispose();
	}

	public static final int KEEP_RATIO = -1;

	public static void rotate180(BufferedImage img) {
		int w = img.getWidth();
		int h = img.getHeight();
		int[] rgb = new int[w * h];
		img.getRGB(0, 0, w, h, rgb, 0, w);
		int p = rgb.length;

		int p_2 = p / 2;
		int p_1 = p - 1;
		int tmp;

		for (int i = 0; i < p_2; i++) {
			tmp = rgb[i];
			rgb[i] = rgb[p_1 - i];
			rgb[p_1 - i] = tmp;
		}

		img.setRGB(0, 0, w, h, rgb, 0, w);
	}

	public static BufferedImage rotate90(BufferedImage img, boolean flushOld) {
		int w = img.getWidth();
		int h = img.getHeight();

		int[] rgb_old = img.getRGB(0, 0, w, h, null, 0, w);
		if (flushOld)
			img.flush();
		int[] rgb_new = new int[h * w];

		for (int i = 0; i < w; i++) {
			for (int j = 0; j < h; j++) {
				int x_old = i;
				int y_old = j;
				int p_old = w * y_old + x_old;

				int x_new = j;
				int y_new = w - 1 - i;
				int p_new = h * y_new + x_new;

				rgb_new[p_new] = rgb_old[p_old];
			}
		}

		BufferedImage rot = new BufferedImage(h, w, img.getType());
		rot.setRGB(0, 0, h, w, rgb_new, 0, h);
		return rot;
	}

	public static BufferedImage rotate270(BufferedImage img, boolean flushOld) {
		return rotate90(rotate90(rotate90(img, flushOld), true), true);
	}

	public static void fade(BufferedImage image, float transparancy, BufferedImage trans) {
		if (image.getWidth() != trans.getWidth())
			throw new IllegalArgumentException();
		if (image.getHeight() != trans.getHeight())
			throw new IllegalArgumentException();

		int[] rgb = new int[trans.getWidth() * trans.getHeight()];
		int[] alpha = new int[rgb.length];

		image.getRGB(0, 0, trans.getWidth(), trans.getHeight(), rgb, 0, trans.getWidth());

		if (image.getTransparency() != Transparency.OPAQUE) {
			image.getAlphaRaster().getPixels(0, 0, trans.getWidth(), trans.getHeight(), alpha);
			for (int i = 0; i < alpha.length; i++)
				alpha[i] = (int) (alpha[i] * transparancy);
		} else {
			for (int i = 0; i < alpha.length; i++)
				alpha[i] = (int) (0xFF * transparancy);
		}

		trans.setRGB(0, 0, trans.getWidth(), trans.getHeight(), rgb, 0, trans.getWidth());
		trans.getAlphaRaster().setPixels(0, 0, trans.getWidth(), trans.getHeight(), alpha);
	}

	public static BufferedImage thumbScaleWidthGotoTop(BufferedImage img, int w, int h, int bgcolor) {
		BufferedImage thumbnail = ImageUtil.scale(img, w, KEEP_RATIO);
		if (thumbnail.getHeight() > h) {
			thumbnail = thumbnail.getSubimage(0, 0, w, h);
		} else if (thumbnail.getHeight() < h) {
			BufferedImage larger = new BufferedImage(w, h, thumbnail.getType());
			Graphics g = larger.getGraphics();
			g.setColor(new Color(bgcolor));
			g.fillRect(0, 0, w, h);
			g.drawImage(thumbnail, 0, 0, null);
			g.dispose();
			thumbnail.flush();
			thumbnail = larger;
		}
		return thumbnail;
	}

	//

	public static BufferedImage createRGB(int w, int h) {
		return new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
	}

	public static BufferedImage createARGB(int w, int h) {
		return new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
	}

	//

	public static int[] accessRasterIntArray(BufferedImage src) {
		return ((DataBufferInt) src.getRaster().getDataBuffer()).getData();
	}

	public static byte[] accessRasterByteArray(BufferedImage src) {
		return ((DataBufferByte) src.getRaster().getDataBuffer()).getData();
	}

	//

	public static int findNormalizedType(BufferedImage src) {
		int type = src.getType();
		if (type == BufferedImage.TYPE_CUSTOM) {
			if (src.getColorModel().hasAlpha())
				return BufferedImage.TYPE_INT_ARGB;
			return BufferedImage.TYPE_INT_RGB;
		}
		return type;
	}

	public static BufferedImage copy(BufferedImage src) {
		return ImageUtil.copy(src, findNormalizedType(src));
	}

	public static BufferedImage copy(BufferedImage src, int newType) {
		if (newType == BufferedImage.TYPE_CUSTOM)
			throw new IllegalStateException();

		BufferedImage dst = new BufferedImage(src.getWidth(), src.getHeight(), newType);
		if (dst.getColorModel().hasAlpha())
			ImageUtil.makeTransparent(dst);
		dst.getGraphics().drawImage(src, 0, 0, null);
		return dst;
	}

	public static BufferedImage blitIntoRGB(BufferedImage src, BufferedImage dst) {
		// if (true)
		// return copyIntoRGB(src);

		if (dst == null || src.getWidth() != dst.getWidth() || src.getHeight() != dst.getHeight()) {
			dst = new BufferedImage(src.getWidth(), src.getHeight(), BufferedImage.TYPE_INT_RGB);
		}

		int[] srcRGB = accessRasterIntArray(src);
		int[] dstRGB = accessRasterIntArray(dst);

		System.arraycopy(srcRGB, 0, dstRGB, 0, dstRGB.length);

		return dst;
	}

	public static BufferedImage copyIntoRGB(BufferedImage src) {
		return copy(src, BufferedImage.TYPE_INT_RGB);
	}

	//

	public static BufferedImage scale(BufferedImage img, double d) {
		if (img.getWidth() > img.getHeight())
			return ImageUtil.scale(img, (int) (img.getWidth() * d), KEEP_RATIO);
		return ImageUtil.scale(img, KEEP_RATIO, (int) (img.getHeight() * d));
	}

	public static BufferedImage scale(BufferedImage img, int maxSize) {
		int w = KEEP_RATIO, h = KEEP_RATIO;
		if (img.getWidth() > img.getHeight())
			w = maxSize;
		else
			h = maxSize;
		return scale(img, w, h, true);
	}

	public static BufferedImage scale(BufferedImage img, int w, int h) {
		return scale(img, w, h, true);
	}

	public static BufferedImage scale(BufferedImage img, int w, int h, boolean hq) {
		if (w == KEEP_RATIO && h == KEEP_RATIO)
			return ImageUtil.copy(img);

		if (w == KEEP_RATIO)
			w = (int) (h * ((float) img.getWidth() / img.getHeight()));
		else if (h == KEEP_RATIO)
			h = (int) (w / ((float) img.getWidth() / img.getHeight()));

		if (img.getType() == BufferedImage.TYPE_INT_RGB)
			while (w <= img.getWidth() / 2 && h <= img.getHeight() / 2)
				img = ImageUtil.scaleHalfIntRGB(img);
		// else: cannot use the same trick for scale up!!!

		BufferedImage dst = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
		Image im = img.getScaledInstance(w, h, hq ? Image.SCALE_AREA_AVERAGING : Image.SCALE_FAST);
		Graphics g = dst.getGraphics();
		g.drawImage(im, 0, 0, null);
		g.dispose();
		im.flush();
		return dst;
	}

	//

	public static BufferedImage scaleDoubleIntRGB(BufferedImage src) {
		BufferedImage dst = new BufferedImage(src.getWidth() << 1, src.getHeight() << 1, BufferedImage.TYPE_INT_RGB);
		scaleDoubleIntRGB(src, dst);
		return dst;
	}

	public static void scaleDoubleIntRGB(BufferedImage src, BufferedImage dst) {
		if (src.getWidth() * 2 != dst.getWidth())
			throw new IllegalStateException();
		if (src.getHeight() * 2 != dst.getHeight())
			throw new IllegalStateException();

		int w = dst.getWidth();
		int h = dst.getHeight();

		int[] orig = accessRasterIntArray(src);
		int[] full = accessRasterIntArray(dst);

		if (w * h / 4 != orig.length)
			throw new IllegalStateException();
		if (w * h != full.length)
			throw new IllegalStateException();

		final int s1 = 0;
		final int s2 = 8;
		final int s3 = 16;

		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				int rgb1 = orig[(y >> 1) * (w >> 1) + (x >> 1)];
				int rgb2 = orig[(y >> 1) * (w >> 1) + (x >> 1)];
				int rgb3 = orig[(y >> 1) * (w >> 1) + (x >> 1)];
				int rgb4 = orig[(y >> 1) * (w >> 1) + (x >> 1)];

				int r = (((rgb1 >> s3) + (rgb2 >> s3) + (rgb3 >> s3) + (rgb4 >> s3)) >> 2) & 0xFF;
				int g = (((rgb1 >> s2) + (rgb2 >> s2) + (rgb3 >> s2) + (rgb4 >> s2)) >> 2) & 0xFF;
				int b = (((rgb1 >> s1) + (rgb2 >> s1) + (rgb3 >> s1) + (rgb4 >> s1)) >> 2) & 0xFF;

				full[y * w + x] = (r << s3) | (g << s2) | (b << s1);
			}
		}
	}

	/**
	 * Scales image by half. If the dimensions are not multiples of two, the
	 * trailing right column and/or bottom row will be discarded.
	 */

	public static BufferedImage scaleHalfIntRGB(BufferedImage src) {
		BufferedImage dst = new BufferedImage(src.getWidth() >> 1, src.getHeight() >> 1, BufferedImage.TYPE_INT_RGB);
		ImageUtil.scaleHalfIntRGB(src, dst);
		return dst;
	}

	/**
	 * Scales image by half. If the dimensions are not multiples of two, the
	 * trailing right column and/or bottom row will be discarded.
	 */

	public static void scaleHalfIntRGB(BufferedImage src, BufferedImage dst) {
		// if (src.getWidth() % 2 != 0)
		// throw new IllegalStateException();
		// if (src.getHeight() % 2 != 0)
		// throw new IllegalStateException();
		if (src.getWidth() / 2 != dst.getWidth())
			throw new IllegalStateException();
		if (src.getHeight() / 2 != dst.getHeight())
			throw new IllegalStateException();

		int wSrc = src.getWidth();
		int hSrc = src.getHeight();
		int wDst = wSrc >> 1;
		int hDst = hSrc >> 1;

		int[] full = accessRasterIntArray(src);
		int[] half = accessRasterIntArray(dst);

		if (wSrc * hSrc != full.length)
			throw new IllegalStateException();
		if (wDst * hDst != half.length)
			throw new IllegalStateException();

		for (int y = 0; y < hDst; y++) {
			int y0 = (y << 1) | 0;
			int y1 = (y << 1) | 1;

			for (int x = 0; x < wDst; x++) {
				int x0 = (x << 1) | 0;
				int x1 = (x << 1) | 1;

				int rgb1 = full[y0 * wSrc + x0];
				int rgb2 = full[y1 * wSrc + x0];
				int rgb3 = full[y0 * wSrc + x1];
				int rgb4 = full[y1 * wSrc + x1];

				// int r = (((rgb1 & 0xFF0000) + (rgb2 & 0xFF0000) + (rgb3 &
				// 0xFF0000) + (rgb4 & 0xFF0000)) >> (16 + 2));
				// int g = (((rgb1 & 0x00FF00) + (rgb2 & 0x00FF00) + (rgb3 &
				// 0x00FF00) + (rgb4 & 0x00FF00)) >> (8 + 2));
				// int b = (((rgb1 & 0x0000FF) + (rgb2 & 0x0000FF) + (rgb3 &
				// 0x0000FF) + (rgb4 & 0x0000FF)) >> (0 + 2));

				int r_b = (((rgb1 & 0xFF00FF) + (rgb2 & 0xFF00FF) + (rgb3 & 0xFF00FF) + (rgb4 & 0xFF00FF)) >> 2);
				int _g_ = (((rgb1 & 0x00FF00) + (rgb2 & 0x00FF00) + (rgb3 & 0x00FF00) + (rgb4 & 0x00FF00)) >> 2);

				half[y * wDst + x] = (r_b & 0xFF0000) | (_g_ & 0x00FF00) | ((r_b & 0x0000FF) << 0);
			}
		}
	}

	public static BufferedImage fillInto(BufferedImage img, int w, int h) {
		BufferedImage into = new BufferedImage(w, h, findNormalizedType(img));
		if (into.getColorModel().hasAlpha())
			ImageUtil.makeTransparent(into);

		float xScaledownFactor = (float) img.getWidth() / into.getWidth();
		float yScaledownFactor = (float) img.getHeight() / into.getHeight();

		float scaledownFactor = Math.min(xScaledownFactor, yScaledownFactor);

		int wNew = (int) (img.getWidth() / scaledownFactor);
		int hNew = (int) (img.getHeight() / scaledownFactor);
		int xNew = -(wNew - into.getWidth()) / 2;
		int yNew = -(hNew - into.getHeight()) / 2;

		Image tmp = img.getScaledInstance(wNew, hNew, Image.SCALE_AREA_AVERAGING);
		img.flush();

		into.getGraphics().drawImage(tmp, xNew, yNew, null);
		tmp.flush();

		return into;
	}

	public static BufferedImage fitInto(BufferedImage img, int w, int h, int bgcolor) {
		return fitInto(img, w, h, new Insets(0, 0, 0, 0), bgcolor);
	}

	public static BufferedImage fitInto(BufferedImage img, int w, int h, Insets insets, int bgcolor) {
		float srcRatio = (float) img.getWidth() / img.getHeight();
		float dstRatio = (float) w / h;

		int wImgScaled;
		int hImgScaled;

		if (dstRatio < srcRatio) {
			wImgScaled = w - insets.left - insets.right;
			hImgScaled = (int) (wImgScaled / srcRatio);
		} else {
			hImgScaled = h - insets.top - insets.bottom;
			wImgScaled = (int) (hImgScaled * srcRatio);
		}

		BufferedImage dst = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
		Graphics g = dst.getGraphics();
		if ((bgcolor & 0xFF000000) != 0x00) {
			g.setColor(new Color(bgcolor));
			g.fillRect(0, 0, w, h);
		}

		int x = insets.left + ((w - insets.left - insets.right) - wImgScaled) / 2;
		int y = insets.top + ((h - insets.top - insets.bottom) - hImgScaled) / 2;

		BufferedImage scaled = ImageUtil.scale(img, wImgScaled, hImgScaled);
		g.drawImage(scaled, x, y, null);
		scaled.flush();

		return dst;
	}

	public static BufferedImage replaceColor(BufferedImage src, int cSearch, int cReplace) {
		int w = src.getWidth();
		int h = src.getHeight();

		int[] srcRGB = new int[w * h];
		int[] dstRGB = new int[w * h];
		int[] dstA = new int[w * h];

		src.getRGB(0, 0, w, h, srcRGB, 0, w);

		for (int i = 0; i < srcRGB.length; i++) {
			if ((srcRGB[i] & 0xFFFFFF) == cSearch) {
				dstRGB[i] = cReplace & 0xFFFFFF;
				dstA[i] = (cReplace >> 24) & 0xFF;
			} else {
				dstRGB[i] = srcRGB[i];
				dstA[i] = 0xFF;
			}
		}

		BufferedImage dst = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		dst.setRGB(0, 0, w, h, dstRGB, 0, w);
		dst.getAlphaRaster().setPixels(0, 0, w, h, dstA);

		return dst;
	}

	//

	public static Dimension getImageSize(byte[] data) {
		try {
			return getImageSize(new ByteArrayInputStream(data));
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		}
	}

	public static Dimension getImageSize(File file) throws IOException {
		return ImageUtil.getImageSize(new FileInputStream(file));
	}

	public static Dimension getImageSize(InputStream in) throws IOException {
		ImageMetaData meta = getImageTypeAndSize(in);
		return new Dimension(meta.width, meta.height);
	}

	public static ImageMetaData getImageTypeAndSize(byte[] data) throws IOException {
		return getImageTypeAndSize(new ByteArrayInputStream(data));
	}

	//

	public static class ImageMetaData {
		public final ImageType type;
		public final int width;
		public final int height;

		public ImageMetaData(ImageType type, int width, int height) {
			this.type = type;
			this.width = width;
			this.height = height;
		}

		public Dimension getDimension() {
			return new Dimension(this.width, this.height);
		}

		public String toString() {
			return type.name() + ":" + this.width + "x" + this.height;
		}
	}

	public static ImageMetaData getImageTypeAndSize(InputStream in) throws IOException {
		DataInputStream dis = new DataInputStream(new BufferedInputStream(in));

		try {
			int header = dis.readUnsignedShort();

			if (header == 0x8950) {
				// PNG!
				dis.readFully(new byte[(8 - 2) + 4 + 4]); // thanks Abuse

				return new ImageMetaData(ImageType.PNG, dis.readInt(), dis.readInt());
			}

			if (header == 0xffd8) {
				// JPG!

				while (true) {
					int marker = dis.readUnsignedShort();

					switch (marker) {
						case 0xffd8: // SOI
						case 0xffd0: // RST0
						case 0xffd1: // RST1
						case 0xffd2: // RST2
						case 0xffd3: // RST3
						case 0xffd4: // RST4
						case 0xffd5: // RST5
						case 0xffd6: // RST6
						case 0xffd7: // RST7
						case 0xffd9: // EOI
							break;

						case 0xffdd: // DRI
							dis.readUnsignedShort();
							break;

						case 0xffe0: // APP0
						case 0xffe1: // APP1
						case 0xffe2: // APP2
						case 0xffe3: // APP3
						case 0xffe4: // APP4
						case 0xffe5: // APP5
						case 0xffe6: // APP6
						case 0xffe7: // APP7
						case 0xffe8: // APP8
						case 0xffe9: // APP9
						case 0xffea: // APPa
						case 0xffeb: // APPb
						case 0xffec: // APPc
						case 0xffed: // APPd
						case 0xffee: // APPe
						case 0xffef: // APPf
						case 0xfffe: // COM
						case 0xffdb: // DQT
						case 0xffc4: // DHT
						case 0xffda: // SOS
							dis.readFully(new byte[dis.readUnsignedShort() - 2]);
							break;

						case 0xffc0: // SOF0
						case 0xffc2: // SOF2
							dis.readUnsignedShort();
							dis.readByte();
							int height = dis.readUnsignedShort();
							int width = dis.readUnsignedShort();
							return new ImageMetaData(ImageType.JPG, width, height);

						default:
							throw new IllegalStateException("invalid jpg marker: " + Integer.toHexString(marker));
					}
				}
			} else if (header == 0x424D) {
				// BMP!
				dis.readFully(new byte[16]);

				int w = PrimIO.swap32(dis.readInt());
				int h = PrimIO.swap32(dis.readInt());
				return new ImageMetaData(ImageType.BMP, w, h);
			} else if (header == (('G' << 8) | ('I' << 0))) // GIF
			{
				// GIF!
				dis.readFully(new byte[4]);
				int w = PrimIO.swap16(dis.readUnsignedShort());
				int h = PrimIO.swap16(dis.readUnsignedShort());
				return new ImageMetaData(ImageType.GIF, w, h);
			} else
			// TGA?
			{
				// TGA doesn't have a magic number, try to parse
				byte[] tgaRemainingHeader = new byte[18 - 2];
				try {
					dis.readFully(tgaRemainingHeader);
				} catch (EOFException exc) {
					return null;
					// throw new
					// IllegalStateException("unsupported image type. (header: " +
					// Integer.toHexString(header) + ")");
				}

				try {
					if (tgaRemainingHeader[2 - 2] != 2) // uncompressed
						throw new IllegalStateException();
					int w = 0, h = 0;
					w |= (tgaRemainingHeader[12 - 2] & 0xFF) << 0;
					w |= (tgaRemainingHeader[13 - 2] & 0xFF) << 8;
					h |= (tgaRemainingHeader[14 - 2] & 0xFF) << 0;
					h |= (tgaRemainingHeader[15 - 2] & 0xFF) << 8;
					if ((w | h) < 0)
						throw new IllegalStateException();

					boolean alpha;
					if (tgaRemainingHeader[16 - 2] == 24)
						alpha = false;
					else if (tgaRemainingHeader[16 - 2] == 32)
						alpha = true;
					else
						throw new IllegalStateException();
					if (tgaRemainingHeader[17 - 2] != ((alpha ? 8 : 0) & 15))
						throw new IllegalStateException();

					return new ImageMetaData(ImageType.TGA, w, h);
				} catch (IllegalStateException exc) {
					return null;
					// throw new
					// IllegalStateException("unsupported image type. (header: " +
					// Integer.toHexString(header) + ")");
				}
			}
		} finally {
			dis.close();
		}
	}

	//

	public static ImageType getImageType(byte[] data) {
		try {
			return getImageType(new ByteArrayInputStream(data));
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		}
	}

	public static ImageType getImageType(File file) throws IOException {
		if (!file.exists()) {
			// use file extension to determine image type
			return ImageType.valueOf(FileUtil.getExtension(file).toUpperCase());
		}

		return ImageUtil.getImageType(new FileInputStream(file));
	}

	public static ImageType getImageType(InputStream in) throws IOException {
		ImageMetaData meta = ImageUtil.getImageTypeAndSize(in);
		return (meta == null) ? null : meta.type;
	}

	// GIF

	public static BufferedImage convertRGBAToIndexed(BufferedImage src, int transparentColor) {
		BufferedImage dst = new BufferedImage(src.getWidth(), src.getHeight(), BufferedImage.TYPE_BYTE_INDEXED);
		Graphics g = dst.getGraphics();
		g.setColor(new Color(transparentColor));
		g.fillRect(0, 0, dst.getWidth(), dst.getHeight());
		{
			IndexColorModel indexedModel = (IndexColorModel) dst.getColorModel();
			WritableRaster raster = dst.getRaster();
			int sample = raster.getSample(0, 0, 0);
			int size = indexedModel.getMapSize();
			byte[] rr = new byte[size];
			byte[] gg = new byte[size];
			byte[] bb = new byte[size];
			indexedModel.getReds(rr);
			indexedModel.getGreens(gg);
			indexedModel.getBlues(bb);
			IndexColorModel newModel = new IndexColorModel(8, size, rr, gg, bb, sample);
			dst = new BufferedImage(newModel, raster, dst.isAlphaPremultiplied(), null);
		}
		dst.createGraphics().drawImage(src, 0, 0, null);
		return dst;
	}

	public static class GIFStreamer {
		private final ImageWriter iw;
		private final ImageOutputStream ios;
		private final int loopCount;
		private int imageIndex = 0;

		public GIFStreamer(OutputStream out, boolean loop) throws Exception {
			this(out, loop ? 0 : 1); // 0=infinite, 1=once
		}

		public GIFStreamer(OutputStream out, int loopCount) throws Exception {
			this.loopCount = loopCount;

			this.ios = ImageIO.createImageOutputStream(out);

			this.iw = ImageIO.getImageWritersByFormatName("gif").next();
			this.iw.setOutput(this.ios);
			this.iw.prepareWriteSequence(null);
		}

		public void addFrame(GifFrame frame) throws IOException {
			ImageWriteParam iwp = iw.getDefaultWriteParam();
			IIOMetadata metadata = iw.getDefaultImageMetadata(new ImageTypeSpecifier(frame.img), iwp);
			ImageUtil.configureGIFFrame(metadata, String.valueOf(frame.delay / 10L), this.imageIndex++, frame.disposalMethod, this.loopCount);

			iw.writeToSequence(new IIOImage(frame.img, null, metadata), null);

			this.ios.flush();
		}

		public void close() throws IOException {
			this.iw.endWriteSequence();
			this.ios.close();
		}
	}

	public static void saveAnimatedGIF(OutputStream out, List<GifFrame> frames, int loopCount) throws Exception {
		GIFStreamer streamer = new GIFStreamer(out, loopCount);
		for (GifFrame frame : frames)
			streamer.addFrame(frame);
		streamer.close();
	}

	static void configureGIFFrame(IIOMetadata meta, String delayTime, int imageIndex, String disposalMethod, int loopCount) {
		String metaFormat = meta.getNativeMetadataFormatName();

		if (!"javax_imageio_gif_image_1.0".equals(metaFormat)) {
			throw new IllegalArgumentException("Unfamiliar gif metadata format: " + metaFormat);
		}

		Node root = meta.getAsTree(metaFormat);

		Node child = root.getFirstChild();
		while (child != null) {
			if ("GraphicControlExtension".equals(child.getNodeName()))
				break;
			child = child.getNextSibling();
		}

		IIOMetadataNode gce = (IIOMetadataNode) child;
		gce.setAttribute("userDelay", "FALSE");
		gce.setAttribute("delayTime", delayTime);
		gce.setAttribute("disposalMethod", disposalMethod);

		if (imageIndex == 0) {
			IIOMetadataNode aes = new IIOMetadataNode("ApplicationExtensions");
			IIOMetadataNode ae = new IIOMetadataNode("ApplicationExtension");
			ae.setAttribute("applicationID", "NETSCAPE");
			ae.setAttribute("authenticationCode", "2.0");
			byte[] uo = new byte[] { 0x1, (byte) (loopCount & 0xFF), (byte) ((loopCount >> 8) & 0xFF) };
			ae.setUserObject(uo);
			aes.appendChild(ae);
			root.appendChild(aes);
		}

		try {
			meta.setFromTree(metaFormat, root);
		} catch (IIOInvalidTreeException e) {
			throw new Error(e);
		}
	}
}
