package excel.cracker;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import org.apache.poi.poifs.crypt.Decryptor;
import org.apache.poi.poifs.crypt.EncryptionInfo;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

	private static final Logger log = LoggerFactory.getLogger(Main.class);

	// Parameters
	private static final int minPasswordLength = 2;
	private static final int maxPasswordLength = 20;
	private static boolean finished = false;
	private static File inputFile;
	private final static Character[] charSet;
	static {
		// Character set for cracking
		final ArrayList<Character> characters = new ArrayList<>();
		// Numbers
		IntStream.range(48, 58).forEach(i -> characters.add((char) i));
		// Lower case
		IntStream.range(65, 91).forEach(i -> characters.add((char) i));
		// Upper case
		IntStream.range(97, 123).forEach(i -> characters.add((char) i));
		charSet = characters.toArray(new Character[characters.size()]);
	}
	// Thread pool
	private static final int threadCount = Runtime.getRuntime().availableProcessors();

	public static void main(final String[] args) throws IOException {

		if (args.length <= 0) {
			log.error("File can't be null");
			return;
		}
		inputFile = new File(args[0]);

		final ExecutorService threadPoolExecutor = new ThreadPoolExecutor(threadCount, threadCount, 0L,
				TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>());
		final CompletableFuture<String> cf = new CompletableFuture<>();
		final BlockingQueue<String> passwordQueue = new LinkedBlockingQueue<>(threadCount * 2);

		// Runnables to execute
		final Decryptor excelDecryptor = Decryptor.getInstance(new EncryptionInfo(new POIFSFileSystem(inputFile)));
		final Runnable producer = passwordProvider(charSet, passwordQueue, minPasswordLength, maxPasswordLength);
		final Runnable consumer = passwordCracker(cf, passwordQueue, excelDecryptor);

		executeRunnableDesiredTimes(1, threadPoolExecutor, producer);
		executeRunnableDesiredTimes(threadCount - 1, threadPoolExecutor, consumer);

		final String result = crackPassword(threadPoolExecutor, cf);
		log.info("Password found: {}", result);
	}

	private static String crackPassword(final ExecutorService service, final CompletableFuture<String> cf) {
		String result = "";
		try {
			final Instant start = Instant.now();
			result = cf.get();
			final Instant finish = Instant.now();
			final long timeElapsed = Duration.between(start, finish).toMillis();
			log.info("Total time elapsed: {}", timeElapsed);
		} catch (InterruptedException | ExecutionException e) {
			log.error("crackPassword", e);
		} finally {
			service.shutdownNow();
		}
		return result;
	}

	private static void executeRunnableDesiredTimes(final int times, final ExecutorService service,
			final Runnable runnable) {
		IntStream.range(0, times).forEach(value -> service.execute(runnable));
	}

	private static Runnable passwordProvider(final Character[] charSet, final BlockingQueue<String> passwordQueue,
			final int minLen, final int maxLen) {
		return () -> {
			for (int i = minLen; i < maxLen; i++) {
				try {
					generatePasswordsForDesiredLength(charSet, i, "", charSet.length, passwordQueue);
				} catch (final InterruptedException e) {
					log.error("passwordProvider : generatePasswordsForDesiredLength : InterruptedException", e);
				}
			}
		};
	}

	static void generatePasswordsForDesiredLength(final Character[] arr, final int i, final String s, final int length,
			final BlockingQueue<String> passwordQueue) throws InterruptedException {
		if (i == 0) {
			offeing(s, passwordQueue);
		} else {
			for (int j = 0; j < length; j++) {
				generatePasswordsForDesiredLength(arr, i - 1, s + arr[j], length, passwordQueue);
			}
		}
	}

	private static void offeing(final String pass, final BlockingQueue<String> passwordQueue)
			throws InterruptedException {
		log.trace("Offering : {}", pass);
		passwordQueue.offer(pass, 12, TimeUnit.HOURS);
	}

	private static Runnable passwordCracker(final CompletableFuture<String> cf, final BlockingQueue<String> passwordQueue,
			final Decryptor excelDecryptor) {
		return () -> {
			String password = "";
			try {
				while (!finished && !excelDecryptor.verifyPassword(password)) {
					password = passwordQueue.take();
					log.debug("Testing password: {}", password);
				}
				cf.complete(password);
				finished = true;
			} catch (InterruptedException | GeneralSecurityException e) {
				log.error("passwordCracker", e);
			}
		};
	}

}
