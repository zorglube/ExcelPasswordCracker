package excel.cracker;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.IntStream;

import org.apache.poi.poifs.crypt.Decryptor;
import org.apache.poi.poifs.crypt.EncryptionInfo;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

public class Main {

	// Parameters
	private static Instant chronoStart = Instant.now();
	private static AtomicLong test = new AtomicLong(0);
	private static boolean debug = false;
	private static int minPasswordLength;
	private static int maxPasswordLength;
	private static boolean finished = false;
	private static File inputFile;
	private final static Character[] charSet;
	static {
		// Character set for cracking
		final var characters = new ArrayList<Character>();
		// // Numbers
		// IntStream.range(48, 58).forEach(i -> characters.add((char) i));
		// // Lower case
		// IntStream.range(65, 91).forEach(i -> characters.add((char) i));
		// // Upper case
		// IntStream.range(97, 123).forEach(i -> characters.add((char) i));
		IntStream.range(33, 126).forEach(i -> characters.add((char) i));
		charSet = characters.toArray(new Character[characters.size()]);
	}
	// Thread pool
	private static final int threadCount = Runtime.getRuntime().availableProcessors();

	public static void main(final String[] args) throws IOException {

		if (args.length <= 0) {
			System.err.println("File can't be null");
			return;
		}
		Main.inputFile = new File(args[0]);
		Main.minPasswordLength = Integer.parseInt(args[1]);
		Main.maxPasswordLength = Integer.parseInt(args[2]);

		final ExecutorService threadPoolExecutor = new ThreadPoolExecutor(Main.threadCount, Main.threadCount, 0L,
				TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>());
		final var cf = new CompletableFuture<String>();
		final BlockingQueue<String> passwordQueue = new LinkedBlockingQueue<>(Main.threadCount * 2);

		// Runnables to execute
		final var excelDecryptor = Decryptor.getInstance(new EncryptionInfo(new POIFSFileSystem(Main.inputFile)));
		final var producer = Main.passwordProvider(Main.charSet, passwordQueue, Main.minPasswordLength,
				Main.maxPasswordLength);
		final var consumer = Main.passwordCracker(cf, passwordQueue, excelDecryptor);

		Main.executeRunnableDesiredTimes(1, threadPoolExecutor, producer);
		Main.executeRunnableDesiredTimes(Main.threadCount - 1, threadPoolExecutor, consumer);

		final var result = Main.crackPassword(threadPoolExecutor, cf);
		System.out.println(String.format("\nPassword found: %s", result));
	}

	private static String crackPassword(final ExecutorService service, final CompletableFuture<String> cf) {
		var result = "";
		try {
			final var start = Instant.now();
			result = cf.get();
			Files.write(Paths.get("password_found.txt"), Arrays.asList(result), StandardCharsets.UTF_8,
					StandardOpenOption.APPEND);
			final var finish = Instant.now();
			final var timeElapsed = Duration.between(start, finish).toMillis();
			System.out.println(String.format("\nPassword found: %s", result));
			System.out.println(String.format("\nTotal time elapsed: %s", timeElapsed));
		} catch (InterruptedException | ExecutionException | IOException e) {
			System.err.println("\ncrackPassword");
			e.printStackTrace();
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
			for (var i = minLen; i < maxLen; i++) {
				try {
					Main.generatePasswordsForDesiredLength(charSet, i, "", charSet.length, passwordQueue);
				} catch (final InterruptedException e) {
					System.err.println("\npasswordProvider : generatePasswordsForDesiredLength : InterruptedException");
					e.printStackTrace();
				}
			}
		};
	}

	static void generatePasswordsForDesiredLength(final Character[] arr, final int i, final String s, final int length,
			final BlockingQueue<String> passwordQueue) throws InterruptedException {
		if (i == 0) {
			Main.offeing(s, passwordQueue);
		} else {
			for (var j = 0; j < length; j++) {
				Main.generatePasswordsForDesiredLength(arr, i - 1, s + arr[j], length, passwordQueue);
			}
		}
	}

	private static void offeing(final String pass, final BlockingQueue<String> passwordQueue)
			throws InterruptedException {
		passwordQueue.offer(pass, 12, TimeUnit.HOURS);
	}

	private static Runnable passwordCracker(final CompletableFuture<String> cf, final BlockingQueue<String> passwordQueue,
			final Decryptor excelDecryptor) {
		return () -> {
			var password = "";
			try {
				while (!Main.finished && !excelDecryptor.verifyPassword(password)) {
					password = passwordQueue.take();
					System.out.print(
							String.format("Offering : %s, %010d pw, %10d pw/s, since %d min\r", password, test.incrementAndGet(),
									Math.floorMod(test.get(), Duration.between(chronoStart, Instant.now()).toSeconds() + 1),
									Duration.between(chronoStart, Instant.now()).toMinutes()));
					// if (debug)
					// System.err.printf("Testing password: {}", password);
				}
				cf.complete(password);
				Main.finished = true;
			} catch (InterruptedException | GeneralSecurityException e) {
				System.err.println("\npasswordCracker");
				e.printStackTrace();
			}
		};
	}

}
