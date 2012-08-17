/**
 * Created on 18-mei-2003
 */

package craterstudio.util;

import java.awt.Component;
import java.awt.Dialog;
import java.awt.Frame;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicLong;

import javax.swing.JDialog;

import craterstudio.data.tuples.Duo;
import craterstudio.func.Condition;
import craterstudio.io.Streams;
import craterstudio.text.Text;

public class HighLevel {
	public static String convertThrowableToString(Throwable t) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream stream = new PrintStream(baos);
		t.printStackTrace(stream);
		return Text.utf8(baos.toByteArray());
	}

	public static List<File> lookupClassPath() {
		ClassLoader parent = HighLevel.class.getClassLoader();

		List<File> cp = new ArrayList<File>();

		if (parent instanceof URLClassLoader) {
			URL[] urls = ((URLClassLoader) parent).getURLs();

			for (URL url : urls) {
				String full = url.toExternalForm();

				if (!full.startsWith("file:")) {
					continue;
				}

				cp.add(new File(Text.after(full, "file:")));
			}
		}

		return cp;
	}

	public static Runnable createMainLauncher(String classpath, String mainclass, String... args) throws Exception {
		return createMainLauncher(Text.split(classpath, File.pathSeparatorChar), mainclass, args);
	}

	public static Runnable createMainLauncher(String[] classpath, String mainclass, final String... args) throws Exception {
		URL[] cpURLs = new URL[classpath.length];

		try {
			for (int i = 0; i < cpURLs.length; i++) {
				cpURLs[i] = new File(classpath[i]).toURI().toURL();
			}
		} catch (MalformedURLException exc) {
			throw new IllegalArgumentException(exc);
		}

		URLClassLoader cl = new URLClassLoader(cpURLs);
		Class<?>[] params = new Class[] { String[].class };
		final Method method = cl.loadClass(mainclass).getMethod("main", params);

		return new Runnable() {
			@Override
			public void run() {
				try {
					method.invoke(null, new Object[] { args });
				} catch (InvocationTargetException exc) {
					if (!(exc.getCause() instanceof ThreadDeath))
						throw new IllegalStateException(exc.getCause());
				} catch (Exception exc) {
					exc.printStackTrace();
				}
			}
		};
	}

	public static final int iteratorElements(Iterator<?> it) {
		int counter = 0;
		while (it.hasNext()) {
			it.next();
			counter++;
		}
		return counter;
	}

	public static final <T> T iteratorElement(Iterator<T> it, int n) {
		if (n < 0)
			throw new IllegalArgumentException("n (" + n + ") must be >= 0");

		int m = n;

		while (it.hasNext()) {
			T t = it.next();
			if ((n--) == 0)
				return t;
		}

		throw new NoSuchElementException("element @ " + m + " not available");
	}

	public static final <T> int indexOfIterator(Iterator<T> it, T find) {
		int i = 0;
		while (it.hasNext()) {
			if (it.next().equals(find))
				return i;
			i++;
		}
		return -1;
	}

	public static final <T> int lastIndexOfIterator(Iterator<T> it, T find) {
		int last = -1;
		int i = 0;
		while (it.hasNext()) {
			if (it.next().equals(find))
				last = i;
			i++;
		}
		return last;
	}

	//

	public static final Thread startDaemon(Runnable task) {
		Thread t = new Thread(task);
		t.setDaemon(true);
		t.start();
		return t;
	}

	private static final AtomicLong threadOff = new AtomicLong();

	public static final Thread start(Runnable task) {
		Thread t = new Thread(task);
		t.start();
		return t;
	}

	public static final Thread start(Runnable task, long stacksize) {
		return start(task, "CustomStackSize-" + threadOff.getAndIncrement(), stacksize);
	}

	public static final Thread start(Runnable task, String name, long stacksize) {
		Thread t = new Thread(Thread.currentThread().getThreadGroup(), task, name, stacksize);
		t.start();
		return t;
	}

	public static final void join(Thread t) {
		do {
			try {
				t.join();

				break;
			} catch (InterruptedException exc) {
				// ignore
			}
		} while (true);
	}

	public static final void wait(Object lock) {
		try {
			lock.wait();
		} catch (InterruptedException exc) {
			// ignore
		}
	}

	public static final void wait(Object lock, long ms) {
		try {
			lock.wait(ms);
		} catch (InterruptedException exc) {
			// ignore
		}
	}

	public static final void wait(Object lock, long waitMS, Condition con, boolean consumeInterrupts) {
		synchronized (lock) {
			while (con == null || (con != null && !con.pass())) {
				try {
					lock.wait(waitMS);
				} catch (InterruptedException exc) {
					if (consumeInterrupts) {
						Thread.interrupted();
					}
				}

				if (con == null)
					break;
			}
		}
	}

	public static final void notify(Object lock) {
		synchronized (lock) {
			lock.notify();
		}
	}

	public static final void notifyAll(Object lock) {
		synchronized (lock) {
			lock.notifyAll();
		}
	}

	public static final void sleep(long waitMS, Condition con, boolean consumeInterrupts) {
		while (!con.pass()) {
			HighLevel.sleep(waitMS, consumeInterrupts);
		}
	}

	/**
	 * FIELD TO STRING
	 */

	public static final String fieldToString(Class<?> clazz, int fieldValue, String def) {
		try {
			for (Field field : clazz.getFields())
				if (field.getInt(null) == fieldValue)
					return field.getName();

			for (Field field : clazz.getDeclaredFields())
				if (Modifier.isPublic(field.getModifiers()))
					if (field.getInt(null) == fieldValue)
						return field.getName();
		} catch (Exception exc) {
			if (def == null)
				throw new IllegalArgumentException("Field-value (" + fieldValue + ") not found in class " + clazz.getName());

			return def;
		}

		if (def == null)
			throw new IllegalArgumentException("Field-value (" + fieldValue + ") not found in class " + clazz.getName());

		return def;
	}

	public static final List<String> fieldToStrings(Class<?> clazz, int fieldValue) {
		try {
			List<String> fieldNames = new LinkedList<String>();

			for (Field field : clazz.getFields())
				if (field.getInt(null) == fieldValue)
					fieldNames.add(field.getName());

			for (Field field : clazz.getDeclaredFields())
				if (Modifier.isPublic(field.getModifiers()))
					if (field.getInt(null) == fieldValue)
						fieldNames.add(field.getName());

			if (!fieldNames.isEmpty())
				return fieldNames;
		} catch (Exception exc) {
			throw new IllegalArgumentException(exc);
		}

		throw new IllegalArgumentException("Field-value (" + fieldValue + ") not found in class " + clazz.getName());
	}

	public static final int stringToField(Class<?> clazz, String fieldName, int def) {
		try {
			Field field = clazz.getField(fieldName);
			if (field == null)
				throw new IllegalStateException();
			if (field.getType() != int.class)
				throw new IllegalStateException();
			return ((Integer) field.get(null)).intValue();
		} catch (Exception exc) {
			return def;
		}
	}

	/**
	 * PROPERTIES BY PATH
	 */

	public static final void setPropertyByPath(Object obj, String path, Object val) {
		propertyPathBy(obj, path, val, true);
	}

	public static final Object getPropertyByPath(Object obj, String path) {
		return propertyPathBy(obj, path, null, false);
	}

	private static final Object propertyPathBy(Object obj, String path, Object val, boolean set) {
		String orgPath = path;

		while (true) {
			int dot = path.indexOf('.');

			if (dot == -1) {
				if (set) {
					setProperty(obj, path, val);
					return null;
				}

				return getProperty(obj, path);
			}

			obj = getProperty(obj, path.substring(0, dot));
			if (obj == null)
				throw new NullPointerException("\"" + path.substring(0, dot) + "\"==null in \"" + orgPath + "\"");
			path = path.substring(dot + 1);
		}
	}

	/**
	 * PROPERTIES
	 */

	public static final void setProperty(Object obj, String property, Object val) {
		String methodName = "set" + Text.capitalize(property);

		for (Method method : obj.getClass().getMethods()) {
			if (!method.getName().equals(methodName))
				continue;

			if (method.getReturnType() != void.class)
				throw new IllegalStateException("Invalid property: " + property + ", return-type must be void");

			if (method.getParameterTypes().length != 1)
				throw new IllegalStateException("Invalid property: " + property + ", must have 1 parameter");

			try {
				method.invoke(obj, new Object[] { val });
				return;
			} catch (IllegalArgumentException exc) {
				throw new IllegalStateException("" + exc.getMessage() + " prop=" + property + ", val=" + val.getClass().getSimpleName() + ", par=" + method.getParameterTypes()[0].getSimpleName());
			} catch (Exception exc) {
				throw new IllegalStateException(exc);
			}
		}

		throw new IllegalStateException("Couldn't find property: " + property + " as " + methodName);
	}

	public static final Object getProperty(Object obj, String property) {
		for (int i = 0; i < 2; i++) {
			String methodName = ((i == 0) ? "get" : "is") + Text.capitalize(property);

			for (Method method : obj.getClass().getMethods()) {
				if (!method.getName().equals(methodName))
					continue;

				if (method.getReturnType() == void.class)
					throw new IllegalStateException("Invalid property: " + property + ", return-type must not be void");

				if (method.getParameterTypes().length != 0)
					throw new IllegalStateException("Invalid property: " + property + ", must have 0 parameters");

				try {
					return method.invoke(obj, new Object[0]);
				} catch (Exception exc) {
					throw new IllegalStateException(exc);
				}
			}
		}

		throw new IllegalStateException("Couldn't find property: " + property);
	}

	/**
	 * GC
	 */

	public static final long gc() {
		long preUsed = HighLevel.memUsed();
		for (int i = 0; i < 4; i++)
			System.gc();
		long postUsed = HighLevel.memUsed();

		return preUsed - postUsed;
	}

	public static long memUsed() {
		Runtime r = Runtime.getRuntime();
		return r.totalMemory() - r.freeMemory();
	}

	//

	/**
    *    
    */

	public static final Duo<byte[]> executeProcess(String... cmds) {
		try {
			Process proc = Runtime.getRuntime().exec(cmds);
			ByteArrayOutputStream stdout = new ByteArrayOutputStream();
			ByteArrayOutputStream stderr = new ByteArrayOutputStream();
			Streams.asynchronousTransfer(proc.getInputStream(), stdout);
			Streams.asynchronousTransfer(proc.getErrorStream(), stderr);
			int exitCode = proc.waitFor();
			if (exitCode != 0)
				throw new IllegalStateException("exit-code: " + exitCode + " cmds=" + Arrays.toString(cmds));

			return new Duo<byte[]>(stdout.toByteArray(), stderr.toByteArray());
		} catch (Exception exc) {
			throw new IllegalStateException(exc);
		}
	}

	/**
	 * SLEEP
	 */

	public static final void busySleep(long ms) {
		busyNanoSleep(ms * 1000000L);
	}

	public static final void busyNanoSleep(long ns) {
		long end = System.nanoTime() + ns;
		while (System.nanoTime() < end)
			Thread.yield();
	}

	public static final void sleep() {
		long tenYears = 10 * 365L * 24L * 3600L * 1000L;

		try {
			Thread.sleep(tenYears);
		} catch (InterruptedException exc) {
			return;
		}
	}

	public static final void sleep(long ms) {
		sleep(ms, false);
	}

	public static final void sleep(long ms, boolean consumeInterrupts) {
		try {
			Thread.sleep(ms);
		} catch (InterruptedException exc) {
			if (consumeInterrupts) {
				Thread.currentThread().interrupt();
				Thread.interrupted();
			}
		}
	}

	public static final int sizeof(Class<?> prim) {
		if (prim == byte.class || prim == boolean.class)
			return 1;
		if (prim == short.class || prim == char.class)
			return 2;
		if (prim == int.class || prim == float.class)
			return 4;
		if (prim == long.class || prim == double.class)
			return 8;
		return -1;
	}

	public static JDialog createDialogFromComponentParent(Component c, boolean modal, boolean root) {
		Component target = null;

		while (c.getParent() != null) {
			c = c.getParent();

			if (c instanceof Frame) {
				target = c;
				if (!root)
					break;
			}

			if (c instanceof Dialog) {
				target = c;
				if (!root)
					break;
			}
		}

		if (target instanceof Frame)
			return new JDialog((Frame) target, modal);
		if (target instanceof Dialog)
			return new JDialog((Dialog) target, modal);

		throw new IllegalStateException("Couldn't find root surface");
	}

	//

	public static Field findDeclaredField(Class<?> clazz, String name) {
		do {
			for (Field fld : clazz.getDeclaredFields())
				if (fld.getName().equals(name))
					return fld;

			clazz = clazz.getSuperclass();
		} while (clazz != null);

		return null;
	}

	public static Field[] findDeclaredFields(Class<?> clazz, String name) {
		List<Field> result = new ArrayList<Field>();

		do {
			for (Field fld : clazz.getDeclaredFields())
				if (fld.getName().equals(name))
					result.add(fld);

			clazz = clazz.getSuperclass();
		} while (clazz != null);

		return result.toArray(new Field[result.size()]);
	}

	//

	public static Method findDeclaredMethod(Class<?> clazz, String name) {
		do {
			for (Method mthd : clazz.getDeclaredMethods())
				if (mthd.getName().equals(name))
					return mthd;

			clazz = clazz.getSuperclass();
		} while (clazz != null);

		return null;
	}

	public static Method[] findDeclaredMethods(Class<?> clazz, String name) {
		Class<?> clz = clazz;
		List<Method> result = new ArrayList<Method>();

		try {
			do {
				outer: for (Method mthd1 : clazz.getDeclaredMethods()) {
					if (!mthd1.getName().equals(name))
						continue; // not interested

					for (Method mthd2 : result) {
						// can still be overridden with WIDER modifiers
						// if(mthd1.getModifiers() != mthd2.getModifiers())
						// continue;

						if (!mthd1.getReturnType().equals(mthd2.getReturnType()))
							continue; // not equal

						Class<?>[] c1 = mthd1.getParameterTypes();
						Class<?>[] c2 = mthd2.getParameterTypes();
						if (!Arrays.equals(c1, c2))
							continue; // not equal

						// is overriden by superclass, don't mention
						continue outer;
					}

					// found new method
					result.add(mthd1);
				}

				clazz = clazz.getSuperclass();
			} while (clazz != null);
		} catch (AccessControlException exc) {
			result.clear();
			for (Method mthd : clz.getMethods())
				if (mthd.getName().equals(name))
					result.add(mthd);
		}

		return result.toArray(new Method[result.size()]);
	}

	//

	public static Field[] forceAccess(Field... flds) {
		try {
			for (Field fld : flds)
				if (!fld.isAccessible())
					fld.setAccessible(true);
		} catch (AccessControlException exc) {
			// ignore
		}

		return flds;
	}

	public static Method[] forceAccess(Method... mthds) {
		try {
			for (Method mthd : mthds)
				if (!mthd.isAccessible())
					mthd.setAccessible(true);
			return mthds;
		} catch (AccessControlException exc) {
			// ignore
		}

		return mthds;
	}

	public static List<URL> getBootClassPath() {
		String a = System.getProperty("sun.boot.class.path");
		String b = System.getProperty("path.separator");

		List<URL> urls = new ArrayList<URL>();
		for (String p : Text.split(a, b)) {
			try {
				urls.add(new File(p).toURI().toURL());
			} catch (IOException exc) {
				exc.printStackTrace();
			}
		}
		return urls;
	}

	public static List<URL> getClassPath() {
		String a = System.getProperty("java.class.path");
		String b = System.getProperty("path.separator");

		List<URL> urls = new ArrayList<URL>();
		for (String p : Text.split(a, b)) {
			try {
				urls.add(new File(p).toURI().toURL());
			} catch (IOException exc) {
				exc.printStackTrace();
			}
		}
		return urls;
	}

	public static List<URL> getClassPath0() {
		try {
			ClassLoader loader = HighLevel.class.getClassLoader();

			if (loader instanceof URLClassLoader) {
				URLClassLoader ucl = (URLClassLoader) loader;
				return Arrays.asList(ucl.getURLs());
			}
		} catch (Exception exc) {
			exc.printStackTrace();
		}

		return null;
	}

	public static List<File> getJarsOnClassPath() {
		List<File> files = new ArrayList<File>();

		try {
			ClassLoader loader = HighLevel.class.getClassLoader();

			if (loader instanceof URLClassLoader) {
				URLClassLoader ucl = (URLClassLoader) loader;
				for (URL url : ucl.getURLs()) {
					String full = url.toString();
					if (!full.startsWith("file:")) {
						continue;
					}

					String path = Text.after(full, "file:");

					File file = new File(path);
					if (!file.exists() || file.isDirectory()) {
						continue;
					}

					files.add(file);
				}
			}
		} catch (Exception exc) {
			exc.printStackTrace();
		}

		return files;
	}
}