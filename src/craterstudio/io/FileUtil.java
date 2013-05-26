/*
 * Created on 16-mrt-2007
 */

package craterstudio.io;

import java.awt.Dialog;
import java.awt.FileDialog;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileSystemView;

import craterstudio.func.DataSource;
import craterstudio.func.DataSourceUtil;
import craterstudio.func.Filter;
import craterstudio.text.Text;
import craterstudio.util.IteratorUtil;

public class FileUtil {
	public static File getHomeDirectory() {
		try {
			return FileSystemView.getFileSystemView().getHomeDirectory();
		} catch (SecurityException exc) {
			// windows 7
			return null;
		}
	}

	public static File getDefaultDirectory() {
		try {
			return FileSystemView.getFileSystemView().getDefaultDirectory();
		} catch (SecurityException exc) {
			// Windows 7
			return null;
		}
	}

	private static File lastBrowseDir;

	public static synchronized File browse(File dir, String title, int dialogMode) {
		if (dir == null)
			dir = (lastBrowseDir != null) ? lastBrowseDir : FileUtil.getDefaultDirectory();
		final File directory = dir;

		final FileDialog dialog = new FileDialog((Dialog) null, title, dialogMode);

		Runnable task = new Runnable() {
			@Override
			public void run() {
				String path = directory == null ? null : directory.getAbsolutePath();
				dialog.setDirectory(path);
				dialog.setVisible(true);
			}
		};

		try {
			if (SwingUtilities.isEventDispatchThread())
				task.run();
			else
				SwingUtilities.invokeAndWait(task);
		} catch (Exception exc) {
			exc.printStackTrace();
		}

		if (dialog.getFile() == null) {
			return null;
		}

		File file = new File(dialog.getDirectory(), dialog.getFile());
		lastBrowseDir = file.getParentFile();
		return file;
	}

	public static File getApplicationDirectory(String appName) {
		File appdata;

		if (System.getProperty("os.name").contains("Windows"))
			appdata = new File(System.getenv("appdata"));
		else
			appdata = new File(System.getProperty("user.home"));

		File appdir = new File(appdata, appName);
		if (!appdir.exists() && !appdir.mkdir())
			throw new IllegalStateException("failed to create application directory for: " + appName);
		return appdir;
	}

	public static final String getExtension(File file) {
		String name = file.getName();
		int indexOf = name.lastIndexOf('.');
		if (indexOf == -1)
			return null;
		return name.substring(indexOf + 1);
	}

	public static final File setExtension(File file, String newExt) {
		String name = file.getName();
		String ext = FileUtil.getExtension(file);

		if (ext != null)
			name = name.substring(0, name.length() - ext.length()) + "." + newExt;

		return new File(file.getParent(), file.getName() + "." + newExt);
	}

	//

	public static Iterable<File> getFileHierachyIterable(File dir) {
		return IteratorUtil.foreach(FileUtil.getFileHierachyIterator(dir, null));
	}

	public static Iterable<File> getFileHierachyIterable(File dir, FileFilter filter) {
		return IteratorUtil.foreach(FileUtil.getFileHierachyIterator(dir, filter));
	}

	//

	public static Iterator<File> getFileHierachyIterator(File dir) {
		return FileUtil.getFileHierachyIterator(dir, null);
	}

	public static Iterator<File> getFileHierachyIterator(File dir, FileFilter filter) {
		return FileUtil.getFileHierachyIterator(dir, filter, null);
	}

	public static Iterator<File> getFileHierachyIterator(final File dir, final FileFilter filter, final Comparator<File> sorter) {
		// convert FileFilter t Filter<File>
		Filter<File> filter2 = filter == null ? null : new Filter<File>() {
			@Override
			public boolean accept(File item) {
				return filter.accept(item);
			}
		};
		return DataSourceUtil.asIterator(getFileHierachySource(dir, filter2, null, sorter));
	}

	public static DataSource<File> getFileHierachySource(final File dir, final Filter<File> directoryFilter, final Filter<File> fileFilter, final Comparator<File> sorter) {
		if (!dir.isDirectory()) {
			throw new IllegalStateException("not a directory: " + dir);
		}

		String[] names = dir.list();
		if (names == null) {
			return DataSourceUtil.empty();
		}

		{
			Arrays.sort(names, String.CASE_INSENSITIVE_ORDER);
		}

		List<File> files = new ArrayList<File>();
		for (int i = 0; i < names.length; i++) {
			File file = new File(dir, names[i]);
			if (!file.isDirectory() || directoryFilter == null || directoryFilter.accept(file)) {
				files.add(file);
			}
		}

		if (sorter != null) {
			Collections.sort(files, sorter);
		}

		final DataSource<File> currDirDataSource = DataSourceUtil.fromIterable(files);

		DataSource<File> recursiveDataSource = new DataSource<File>() {
			private DataSource<File> childStream;

			@Override
			public File produce() throws NoSuchElementException {
				for (;;) {
					if (childStream != null) {
						try {
							return childStream.produce();
						} catch (NoSuchElementException exc) {
							childStream = null;
						}
					}

					File file = currDirDataSource.produce();
					if (file.isDirectory()) {
						childStream = getFileHierachySource(file, directoryFilter, fileFilter, sorter);
					}
					return file;
				}
			}
		};

		if (fileFilter != null) {
			recursiveDataSource = DataSourceUtil.filter(recursiveDataSource, fileFilter);
		}

		return recursiveDataSource;
	}

	@SuppressWarnings("unused")
	public static final int countFilesInDirectory(File dir) {
		int counter = 0;
		for (File file : FileUtil.getFileHierachyIterable(dir))
			counter++;
		return counter;
	}

	public static final int deleteDirectory(File dir, boolean removeSelf) {
		if (!dir.exists())
			return -1;

		if (!dir.isDirectory())
			throw new IllegalStateException("argument must be directory");

		int counter = 0;

		LinkedList<File> dirs = new LinkedList<File>();

		for (File file : FileUtil.getFileHierachyIterable(dir)) {
			if (file.isDirectory())
				dirs.add(file);
			else if (file.delete())
				counter++;
			else
				throw new IllegalStateException("could not remove file: " + file.getAbsolutePath());
		}

		while (!dirs.isEmpty())
			if (dirs.removeLast().delete())
				counter++;
			else
				throw new IllegalStateException("could not remove file: " + dir.getAbsolutePath());

		if (removeSelf)
			if (dir.delete())
				counter++;
			else
				throw new IllegalStateException("could not remove file: " + dir.getAbsolutePath());

		return counter;
	}

	public static final boolean isInDirectory(File file, File base) {
		String f = prepare(file);
		String b = prepare(base);

		return f.startsWith(b) && !f.equals(b);
	}

	public static final String getRelativePath(File file, File base) {
		String f = prepare(file);
		String b = prepare(base);

		if (f.startsWith(b))
			return f.substring(b.length());
		throw new IllegalStateException(f + " not in " + b);
	}

	public static final String getRelativePath(File file, String preparedBasePath) {
		String path = prepare(file);

		if (path.startsWith(preparedBasePath))
			return path.substring(preparedBasePath.length());
		throw new IllegalStateException(path + " not in " + preparedBasePath);
	}

	public static String prepare(File file) {
		try {
			String path = Text.replace(file.getCanonicalPath(), '\\', '/');
			if (file.isDirectory() && !path.endsWith("/"))
				path += "/";
			return path;
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		}
	}

	/**
	 * PATH
	 */

	public static final String getPathToFile(String filename) {
		String sep = "/";

		if (filename.contains("/"))
			sep = "/";
		else if (filename.contains("\\"))
			sep = "\\";

		return filename.substring(0, filename.lastIndexOf(sep));
	}

	public static final boolean ensureFile(File file) {
		FileUtil.ensurePathToFile(file);

		if (!file.exists()) {
			try {
				file.createNewFile();
			} catch (IOException exc) {
				return false;
			}
		}

		return true;
	}

	public static final void ensurePathToFile(File file) {
		if (file.exists()) {
			return;
		}

		FileUtil.ensurePathToDirectory(file.getParentFile());
	}

	public static final void ensurePathToDirectory(File dir) {
		if (dir.exists()) {
			if (!dir.isDirectory())
				throw new IllegalStateException("file already exists, but is not a directory: " + dir.getAbsolutePath());
			return;
		}

		if (!dir.mkdirs())
			throw new IllegalStateException("could not ensure directory: " + dir.getAbsolutePath());
	}

	public static final String switchExtension(String path, String newExt) {
		return path.substring(0, path.lastIndexOf('.') + 1) + newExt;
	}

	public static final String appendDirectory(String path, String dir) {
		int index = -1;

		if (path.lastIndexOf('/') > index)
			index = path.lastIndexOf('/');

		if (path.lastIndexOf('\\') > index)
			index = path.lastIndexOf('\\');

		if (index == -1)
			return path + '/' + dir;

		return path.substring(0, index + 1) + dir + path.substring(index + 1);
	}

	/**
	 * READ
	 */

	public static final byte[] readFile(File file) {
		if (!file.exists()) {
			throw new IllegalArgumentException("File not found: " + file.getAbsolutePath());
		}

		if (file.isDirectory()) {
			return null;
		}

		try {
			byte[] raw = new byte[(int) file.length()];
			Streams.readStreamTo(new FileInputStream(file), raw, 64 * 1024);
			return raw;
		} catch (Exception exc) {
			throw new IllegalStateException(exc);
		}
	}

	public static final ByteBuffer readFileAsBuffer(File file) {
		if (!file.exists()) {
			throw new IllegalArgumentException("File not found: " + file.getAbsolutePath());
		}

		try {
			return Streams.readStream(new FileInputStream(file).getChannel());
		} catch (Exception exc) {
			throw new IllegalStateException(exc);
		}
	}

	public static final void appendFile(File file, byte[] data) {
		if (!file.exists()) {
			ensurePathToFile(file);
		}

		try {
			Streams.writeStream(new FileOutputStream(file, true), data);
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		}
	}

	public static final void writeFile(File file, byte[] data) {
		if (!file.exists()) {
			ensurePathToFile(file);
		} else {
			RandomAccessFile raf = null;

			try {
				raf = new RandomAccessFile(file, "rw");
				raf.setLength(data.length);
				raf.write(data);
			} catch (IOException exc) {
				throw new IllegalStateException(exc);
			} finally {
				Streams.safeClose(raf);
			}

			return;
		}

		try {
			Streams.writeStream(new FileOutputStream(file), data);
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		}
	}

	public static final void writeFile(File file, ByteBuffer data) {
		if (!file.exists()) {
			ensurePathToFile(file);
		}

		try {
			Streams.writeStream(new FileOutputStream(file).getChannel(), data);
		} catch (IOException exc) {
			throw new IllegalStateException(exc);
		}
	}

	public static final void deleteFile(File file) throws IOException {
		if (file.delete()) {
			return;
		}

		if (!file.exists()) {
			throw new FileNotFoundException(file.getAbsolutePath());
		}

		if (file.isDirectory() && file.list().length != 0) {
			throw new IOException("cannot delete non-empty directory: " + file.getAbsolutePath());
		}

		throw new IOException("failed to delete file for unknown reason: " + file.getAbsolutePath());
	}

	public static final void moveFile(File src, File dst) throws IOException {
		if (!src.exists()) {
			throw new FileNotFoundException(src.getAbsolutePath());
		}

		if (dst.exists()) {
			dst.delete();
		}

		if (src.renameTo(dst)) {
			return;
		}

		FileUtil.copyFile(src, dst);

		if (!src.delete()) {
			throw new IOException("failed to delete source file after copy: " + src);
		}
	}

	public static final void copyDirectory(File src, File dst) throws IOException {
		copyDirectory(src, dst, false);
	}

	public static final void copyDirectory(File src, File dst, boolean verbose) throws IOException {
		if (!src.isDirectory())
			throw new IllegalStateException("not a directory: " + src.getAbsolutePath());
		if (!dst.isDirectory())
			throw new IllegalStateException("not a directory: " + dst.getAbsolutePath());

		src = src.getCanonicalFile();
		dst = dst.getCanonicalFile();

		{
			String a = src.getAbsolutePath();
			String b = dst.getAbsolutePath();
			if (a.startsWith(b))
				throw new IllegalStateException("src contains dst");
			if (b.startsWith(a))
				throw new IllegalStateException("dst contains src");
		}

		Iterator<File> it = FileUtil.getFileHierachyIterator(src);
		while (it.hasNext()) {
			File f1 = it.next();
			String rel = FileUtil.getRelativePath(f1, src);
			File f2 = new File(dst, rel);

			if (f1.isDirectory()) {
				if (verbose)
					System.out.println("copying directory: " + rel);
				f2.mkdirs();
			} else {
				if (verbose)
					System.out.println("copying file: " + rel);
				FileUtil.copyFile(f1, f2);
			}
		}
	}

	public static final void copyFile(File src, File dst) throws IOException {
		RandomAccessFile rafsrc = null;
		RandomAccessFile rafdst = null;

		try {
			ensurePathToFile(dst);

			rafsrc = new RandomAccessFile(src, "r");
			rafdst = new RandomAccessFile(dst, "rw");

			rafdst.setLength(rafsrc.length());

			byte[] buf = new byte[64 * 1024];

			while (true) {
				int actuallyRead = rafsrc.read(buf, 0, buf.length);
				if (actuallyRead == -1)
					break;
				rafdst.write(buf, 0, actuallyRead);
			}

			if (rafdst.getFilePointer() != rafdst.length())
				throw new IOException("filepointer not at end");

			if (src.length() != dst.length())
				throw new IOException("src.length != dst.length (" + src.length() + " != " + dst.length() + ")");
		} finally {
			Streams.safeClose(rafsrc);
			Streams.safeClose(rafdst);

			dst.setLastModified(src.lastModified());
		}
	}
}
