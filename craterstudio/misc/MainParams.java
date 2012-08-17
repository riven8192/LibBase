package craterstudio.misc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class MainParams {
	private Set<Character> definedFlags = new HashSet<Character>();
	private Set<Character> definedKeyVals = new HashSet<Character>();
	private Set<String> definedProps = new HashSet<String>();

	public void addFlags(char... cs) {
		for (char c : cs) {
			this.addFlag(c);
		}
	}

	public void addKeyVals(char... cs) {
		for (char c : cs) {
			this.addKeyVal(c);
		}
	}

	public void addProps(String... ss) {
		for (String s : ss) {
			this.addProp(s);
		}
	}

	public void addFlag(char c) {
		if (definedFlags.contains(Character.valueOf(c))) {
			throw new IllegalArgumentException("flag '" + c + "' already defined as flag");
		}
		if (definedKeyVals.contains(Character.valueOf(c))) {
			throw new IllegalArgumentException("flag '" + c + "' already defined as keyval");
		}
		if (definedProps.contains(String.valueOf(c))) {
			throw new IllegalArgumentException("flag '" + c + "' already defined as prop");
		}
		definedFlags.add(Character.valueOf(c));
	}

	public void addKeyVal(char c) {
		if (definedFlags.contains(Character.valueOf(c))) {
			throw new IllegalArgumentException("flag '" + c + "' already defined as flag");
		}
		if (definedKeyVals.contains(Character.valueOf(c))) {
			throw new IllegalArgumentException("flag '" + c + "' already defined as keyval");
		}
		if (definedProps.contains(String.valueOf(c))) {
			throw new IllegalArgumentException("flag '" + c + "' already defined as prop");
		}
		definedKeyVals.add(Character.valueOf(c));
	}

	public void addProp(String prop) {
		if (prop.length() == 0) {
			throw new IllegalArgumentException("prop '" + prop + "' is empty");
		}
		if (prop.length() == 1) {
			char c = prop.charAt(0);
			if (definedFlags.contains(Character.valueOf(c))) {
				throw new IllegalArgumentException("prop '" + prop + "' already defined as flag");
			}
			if (definedKeyVals.contains(Character.valueOf(c))) {
				throw new IllegalArgumentException("prop '" + prop + "' already defined as keyval");
			}
		}
		if (definedProps.contains(prop)) {
			throw new IllegalArgumentException("prop '" + prop + "' already defined as prop");
		}
		definedProps.add(prop);
	}

	private Map<String, String> setProps = new HashMap<String, String>();
	private List<String> setArgs = new ArrayList<String>();

	public String get(String name) {
		if (!setProps.containsKey(name)) {
			throw new IllegalArgumentException("Parameter '" + name + "' not set.");
		}
		return setProps.get(name);
	}

	public int getInt(String name) {
		return Integer.parseInt(get(name));
	}

	public List<String> getArgs() {
		return Collections.unmodifiableList(this.setArgs);
	}

	public boolean isSet(String name) {
		return this.setProps.containsKey(name);
	}

	public void parse(String[] args) {
		for (int i = 0; i < args.length; i++) {
			String param = args[i];

			if (param.startsWith("--")) {
				param = param.substring(2);
				if (!definedProps.contains(param)) {
					throw new IllegalStateException("parameter '" + param + "' not expected");
				}
				setProps.put(param, args[++i]);
			} else if (param.startsWith("-")) {
				param = param.substring(1);

				for (int k = 0; k < param.length(); k++) {
					char c = param.charAt(k);
					if (definedFlags.contains(Character.valueOf(c))) {
						setProps.put(String.valueOf(c), null);
					} else if (definedKeyVals.contains(Character.valueOf(c))) {
						if (k != param.length() - 1 || i == args.length - 1) {
							throw new IllegalStateException("parameter '" + c + "' requires argument");
						}
						setProps.put(String.valueOf(c), args[++i]);
					} else {
						throw new IllegalStateException("parameter '" + c + "' not expected");
					}
				}
			} else {
				while (i < args.length) {
					setArgs.add(args[i++]);
				}
			}
		}
	}
}