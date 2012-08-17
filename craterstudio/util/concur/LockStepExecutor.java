package craterstudio.util.concur;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import craterstudio.func.Transformer;

public class LockStepExecutor<I, O> {
	private final ExecutorService service;

	public LockStepExecutor(ExecutorService service) {
		this.service = service;
	}

	private final List<I> inputs = new ArrayList<>();
	private final List<O> outputs = new ArrayList<>();
	private final List<Future<O>> futures = new ArrayList<>();

	public void addInput(I input) {
		this.inputs.add(input);
	}

	public List<O> lockstep(final Transformer<I, O> task) {

		futures.clear();
		for (final I input : inputs) {
			Callable<O> call = new Callable<O>() {
				@Override
				public O call() throws Exception {
					return task.transform(input);
				}
			};
			futures.add(this.service.submit(call));
		}
		inputs.clear();

		outputs.clear();
		for (Future<O> future : futures) {
			O output;
			try {
				output = future.get();
			} catch (InterruptedException | ExecutionException exc) {
				throw new IllegalStateException(exc);
			}
			outputs.add(output);
		}

		return outputs;
	}
}
