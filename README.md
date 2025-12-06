# -
Решение для "II Онлайн-хакатон по параллельному программированию на языке C#"



using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

var options = RecoverOptions.Parse(args);

// запускаем BenchmarkDotNet.
if (options.RunBenchmarks)
{
	BenchmarkOptionsBridge.Write(options);
	// Запускаем бенчмарки, описанные в классе StegoBenchmarks.
	BenchmarkRunner.Run<StegoBenchmarks>();
	return;
}

var decryptor = new StegoDecryptor(options);
Console.WriteLine("Starting fragment recovery...");
// Запускаем секундомер
var sw = Stopwatch.StartNew();
var recoveryResult = decryptor.Recover(CancellationToken.None);
sw.Stop();

// Сохраняем результаты восстановления (текст, сырые байты, ключи, метаданные).
decryptor.WriteOutputs(recoveryResult);

// Печатаем результаты
Console.WriteLine($"Recovered fragment at char offset {recoveryResult.StartIndex} in {sw.Elapsed}.");
Console.WriteLine($"Plaintext: {options.TextOutPath}");
Console.WriteLine($"Raw bytes: {options.RawOutPath}");
Console.WriteLine($"Recovered key: {options.KeyOutPath}");
Console.WriteLine($"Metadata: {options.InfoOutPath}");

public sealed record RecoverOptions
{
	public string BookPath { get; init; } = Path.GetFullPath("Selyankin_Kogda-truba-zovet.txt");
	public string StegoPath { get; init; } = Path.GetFullPath("stego_data.bin");
	public string TextOutPath { get; init; } = Path.GetFullPath("recovered_fragment.txt");
	public string RawOutPath { get; init; } = Path.GetFullPath("recovered_fragment.bin");
	public string KeyOutPath { get; init; } = Path.GetFullPath("stego_key_recovered.bin");
	public string InfoOutPath { get; init; } = Path.GetFullPath("fragment_info.txt");
	public int FragmentCharLength { get; init; } = 1000;
	
	// Максимальная степень параллелизма
	public int? MaxDegreeOfParallelism { get; init; } = Math.Max(1, Environment.ProcessorCount - 1);

	public bool RunBenchmarks { get; init; } = false;
	public static RecoverOptions Default => new();
	public static RecoverOptions Parse(string[] args)
	{
		var current = Default;
		for (int i = 0; i < args.Length; i++)
		{
			var arg = args[i];
			if (!arg.StartsWith("--", StringComparison.Ordinal))
			{
				continue;
			}

			// флаг --benchmark (без значения)
			if (string.Equals(arg, "--benchmark", StringComparison.OrdinalIgnoreCase))
			{
				current = current with { RunBenchmarks = true };
				continue;
			}

			// Разбираем ключ и значение опции
			string key;
			string? value = null;
			var eqIndex = arg.IndexOf('=');
			if (eqIndex > 0)
			{
				// Формат --key=value: разделяем на ключ и значение.
				key = arg[..eqIndex];
				value = arg[(eqIndex + 1)..];
			}
			else
			{
				// Формат --key value: если следующий аргумент существует и не начинается с --, считаем его значением.
				key = arg;
				if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
				{
					value = args[++i];
				}
			}

			// Нормализация значения
			if (value is not null)
			{
				value = value.Trim();
				if (value.Length == 0)
				{
					value = null;
				}
			}

			switch (key)
			{
				case "--book":
					current = current with { BookPath = RequirePath(value, nameof(BookPath)) };
					break;
				case "--stego":
					current = current with { StegoPath = RequirePath(value, nameof(StegoPath)) };
					break;
				case "--text-out":
					current = current with { TextOutPath = RequirePath(value, nameof(TextOutPath)) };
					break;
				case "--raw-out":
					current = current with { RawOutPath = RequirePath(value, nameof(RawOutPath)) };
					break;
				case "--key-out":
					current = current with { KeyOutPath = RequirePath(value, nameof(KeyOutPath)) };
					break;
				case "--info-out":
					current = current with { InfoOutPath = RequirePath(value, nameof(InfoOutPath)) };
					break;
				case "--char-len":
					current = current with { FragmentCharLength = ParsePositiveInt(value, nameof(FragmentCharLength)) };
					break;
				case "--max-degree":
					current = current with { MaxDegreeOfParallelism = ParsePositiveInt(value, nameof(MaxDegreeOfParallelism)) };
					break;
				default:
					Console.WriteLine($"Warning: Unknown option '{key}'.");
					break;
			}
		}
		return current;

		static string RequirePath(string? path, string name)
		{
			if (string.IsNullOrWhiteSpace(path))
			{
				throw new ArgumentException($"Option '{name}' requires a value.");
			}

			return Path.GetFullPath(path);
		}

		static int ParsePositiveInt(string? value, string name)
		{
			if (!int.TryParse(value, out var parsed) || parsed <= 0)
			{
				throw new ArgumentException($"Option '{name}' must be a positive integer.");
			}

			return parsed;
		}
	}
}

// ----------------------- StegoDecryptor -----------------------
// Основной класс, реализующий логику загрузки контейнеров, восстановления ключей и декодирования фрагмента.
public sealed class StegoDecryptor
{
	// Количество возможных цифр (0..9).
	private const int DigitCount = 10;
	// Магическое число для файла ключей (идентификатор формата записываемого файла).
	private const int KeyMagic = 0x41534B59;
	// Строковые эталоны бит для каждой цифры (последовательности '0'/'1').
	private static readonly string[] Etalons =
	{
		"111111111111111111111111111111111111111111111111111111000000000000000000000000",
		"000000000100000000000000000111111111111111111100000000000000000000000011111111",
		"100000000000000000111111111111111111100000000111111111111111110000000000000000",
		"100000000100000000111111111100000000100000000000000000111111111111111111111111",
		"000000000111111111100000000111111111111111111100000000000000001111111100000000",
		"100000000111111111111111111100000000111111111111111111000000001111111100000000",
		"111111111100000000000000000100000000111111111111111111000000001111111111111111",
		"111111111100000000111111111100000000000000000000000000000000000000000011111111",
		"111111111111111111111111111111111111111111111111111111000000001111111100000000",
		"100000000111111111111111111111111111100000000000000000111111111111111100000000"
	};

	// Количество бит в эталоне.
	private static readonly int BitLength = Etalons[0].Length;
	// Сколько байт занимает контейнер (выравнивание вверх).
	private static readonly int BytePerContainer = (BitLength + 7) >> 3;
	// Сколько байт контейнеров используется для кодирования одного исходного байта (3 контейнера).
	private static readonly int HiddenPerByte = 3 * BytePerContainer;
	// Преобразованные эталоны в виде массивов int (0/1) для быстрого сравнения.
	private static readonly int[][] EtalonBits = BuildEtalonBits();
	// UTF8 без BOM — используется для чтения/записи текста и преобразования в байты.
	private static readonly Encoding Utf8 = new UTF8Encoding(false);

	// Тройки контейнеров, загруженные из стего-файла.
	private readonly ContainerTriple[] _triples;
	// Целевая длина байтов (количество тройных контейнеров).
	private readonly int _targetByteLength;

	// Конструктор: принимает опции, загружает тройки контейнеров и запоминает целевую длину.
	public StegoDecryptor(RecoverOptions options)
	{
		Options = options ?? throw new ArgumentNullException(nameof(options));
		_triples = LoadStegoTriples(options.StegoPath);
		_targetByteLength = _triples.Length;
	}

	// Свойство для доступа к опциям.
	public RecoverOptions Options { get; }
	// Внутренний список тройных контейнеров (чтение доступно для бенчмарков).
	internal IReadOnlyList<ContainerTriple> Triples => _triples;

	// Основная логика восстановления: перебирает фрагменты книги и пытается сопоставить их со стего-пayload.
	public RecoverResult Recover(CancellationToken cancellationToken)
	{
		// Читаем весь текст книги в память в кодировке UTF-8.
		var text = File.ReadAllText(Options.BookPath, Utf8);
		// Проверяем, достаточно ли длинна книги для выбранного фрагмента.
		if (text.Length < Options.FragmentCharLength)
		{
			throw new InvalidOperationException("Book is shorter than the requested fragment length.");
		}

		// Максимальная начальная позиция для окна фиксированного размера.
		var maxStart = text.Length - Options.FragmentCharLength;
		// Создаём партиционер диапазона для Parallel.ForEach.
		var partitioner = Partitioner.Create(0, maxStart + 1);
		// Создаём токен отмены, чтобы остановить все потоки при успехе.
		using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		// Параллельные опции: ограничиваем степень параллелизма.
		var parallelOptions = new ParallelOptions
		{
			MaxDegreeOfParallelism = Options.MaxDegreeOfParallelism ?? Environment.ProcessorCount
		};

		// Здесь будет сохранён первый успешный кандидат (если найден).
		RecoverResult? winner = null;

		// Перебираем диапазон стартов в параллельном режиме.
		Parallel.ForEach(partitioner, parallelOptions, (range, state) =>
		{
			for (int start = range.Item1; start < range.Item2; start++)
			{
				// Если токен отмены выставлен — прекращаем работу текущего потока.
				if (cts.IsCancellationRequested)
				{
					state.Stop();
					return;
				}

				// Извлекаем фрагмент фиксированной длины символов.
				string fragment = text.Substring(start, Options.FragmentCharLength);
				// Переводим фрагмент в UTF-8 байты.
				byte[] fragmentBytes = Utf8.GetBytes(fragment);
				// Если длина байтов не совпадает с целевой — пропускаем кандидат.
				if (fragmentBytes.Length != _targetByteLength)
				{
					continue;
				}

				// Проверяем кандидата: пытаемся восстановить ключи и декодировать.
				var attempt = CheckCandidate(fragment, fragmentBytes, start);
				if (attempt is null)
				{
					continue;
				}

				// Атомарно устанавливаем winner, если он ещё не установлен.
				if (Interlocked.CompareExchange(ref winner, attempt, null) == null)
				{
					// Нашли совпадение: запрашиваем отмену у других потоков и прекращаем.
					cts.Cancel();
					state.Stop();
					return;
				}
			}
		});

		// Если никто не подошёл — бросаем исключение.
		if (winner is null)
		{
			throw new InvalidOperationException("Failed to match any fragment to the stego payload.");
		}

		// Возвращаем результат найденного кандидата.
		return winner;
	}

	// Записывает результаты восстановления в файлы: текст, бинарные данные, файл ключей и инфо-файл.
	public void WriteOutputs(RecoverResult result)
	{
		// Создаём директории для выходных файлов при необходимости.
		EnsureDirectory(Path.GetDirectoryName(Options.TextOutPath));
		EnsureDirectory(Path.GetDirectoryName(Options.RawOutPath));
		EnsureDirectory(Path.GetDirectoryName(Options.KeyOutPath));
		EnsureDirectory(Path.GetDirectoryName(Options.InfoOutPath));

		// Записываем текстовый файл с восстановленным фрагментом в UTF-8.
		File.WriteAllText(Options.TextOutPath, result.FragmentText, Utf8);
		// Записываем сырые декодированные байты.
		File.WriteAllBytes(Options.RawOutPath, result.DecodedBytes);
		// Сохраняем ключи в специальном бинарном формате.
		SaveKeyFile(result.Keys, Options.KeyOutPath);
		// Формируем краткую информацию о результате и записываем в info-файл.
		var info = new StringBuilder()
			.Append("char_offset=").Append(result.StartIndex).AppendLine()
			.Append("byte_length=").Append(result.DecodedBytes.Length).AppendLine()
			.AppendLine("fragment_preview=")
			.Append(result.FragmentText[..Math.Min(result.FragmentText.Length, 200)]).Append("...");
		File.WriteAllText(Options.InfoOutPath, info.ToString(), Utf8);
	}
	// Восстанавливает ключи по известному (plain) массиву байтов и тройкам контейнеров.
	internal static byte[][] RecoverKeysFromPlain(IReadOnlyList<ContainerTriple> triples, IReadOnlyList<byte> plainBytes)
	{
		// Длина plaintext должна совпадать с количеством тройных контейнеров.
		if (triples.Count != plainBytes.Count)
		{
			throw new ArgumentException("Plaintext length must match number of container triples.");
		}

		// eqCounts[digit][bit] — сколько раз для указанной цифры бит совпал с эталоном.
		var eqCounts = new int[DigitCount][];
		for (int i = 0; i < DigitCount; i++)
		{
			eqCounts[i] = new int[BitLength];
		}

		// totals[digit] — сколько раз цифра встречалась в разобранных значениях.
		var totals = new int[DigitCount];

		// Для каждого байта plainBytes разбиваем число на сотни/десятки/единицы и аккумулируем совпадения.
		for (int idx = 0; idx < plainBytes.Count; idx++)
		{
			var (hundreds, tens, ones) = SplitDigits(plainBytes[idx]);
			var triple = triples[idx];
			AccumulateDigit(hundreds, triple.GetSpan(0), eqCounts, totals);
			AccumulateDigit(tens, triple.GetSpan(1), eqCounts, totals);
			AccumulateDigit(ones, triple.GetSpan(2), eqCounts, totals);
		}
		// Сформируем ключи: для каждого бита цифры, если он совпадал во всех вхождениях — считаем его частью ключа.
		var keys = new byte[DigitCount][];
		for (int digit = 0; digit < DigitCount; digit++)
		{
			if (totals[digit] == 0)
			{
				// Если цифра никогда не встречалась — ключ пустой.
				keys[digit] = Array.Empty<byte>();
				continue;
			}

			var buffer = new byte[BytePerContainer];
			for (int bit = 0; bit < BitLength; bit++)
			{
				// Бит считается значимым для ключа только если он совпал во всех найденных вхождениях цифры.
				if (eqCounts[digit][bit] != totals[digit])
				{
					continue;
				}

				int byteIndex = BytePerContainer - 1 - (bit >> 3);
				int bitOffset = bit & 7;
				buffer[byteIndex] |= (byte)(1 << bitOffset);
			}
			keys[digit] = buffer;
		}
		return keys;
	}

	// Декодирует массив байтов используя восстановленные ключи: строит маски и находит цифры по каждому контейнеру.
	internal static byte[] DecodeWithKeys(IReadOnlyList<ContainerTriple> triples, IReadOnlyList<byte[]> keys)
	{
		if (keys.Count != DigitCount)
		{
			throw new ArgumentException("Exactly ten keys are required.");
		}

		// Преобразуем ключи в булевую маску значимых битов для каждой цифры.
		bool[]?[] masks = new bool[]?[DigitCount];
		for (int digit = 0; digit < DigitCount; digit++)
		{
			masks[digit] = BuildMask(keys[digit]);
		}

		// Для каждой тройки контейнеров пытаемся распознать три цифры и склеить их в байт.
		var plaintext = new byte[triples.Count];
		for (int idx = 0; idx < triples.Count; idx++)
		{
			var triple = triples[idx];
			int hundreds = FindDigit(triple.GetSpan(0), masks);
			int tens = FindDigit(triple.GetSpan(1), masks);
			int ones = FindDigit(triple.GetSpan(2), masks);

			// Если хоть одна цифра не распознана — не можем декодировать.
			if (hundreds < 0 || tens < 0 || ones < 0)
			{
				throw new InvalidOperationException("Unable to decode container with recovered masks.");
			}

			int value = hundreds * 100 + tens * 10 + ones;
			if (value > 255)
			{
				throw new InvalidOperationException("Decoded byte exceeds 0xFF.");
			}

			plaintext[idx] = (byte)value;
		}

		return plaintext;
	}

	// Проверяет конкретный фрагмент: восстанавливает ключи и декодирует, затем сравнивает с ожидаемыми байтами.
	private RecoverResult? CheckCandidate(string fragment, byte[] fragmentBytes, int startIndex)
	{
		var keys = RecoverKeysFromPlain(_triples, fragmentBytes);
		byte[] decoded = DecodeWithKeys(_triples, keys);
		if (!decoded.AsSpan().SequenceEqual(fragmentBytes))
		{
			return null;
		}

		// Успех: возвращаем результат восстановления.
		return new RecoverResult(fragment, fragmentBytes, startIndex, keys, decoded);
	}

	// Накопление статистики совпадений для указанной цифры.
	private static void AccumulateDigit(int digit, ReadOnlySpan<byte> container, int[][] eqCounts, int[] totals)
	{
		totals[digit]++;
		var targets = EtalonBits[digit];
		for (int bit = 0; bit < BitLength; bit++)
		{
			// Если бит в контейнере равен эталонному биту — увеличиваем счётчик совпадений.
			if (GetBit(container, bit) == targets[bit])
			{
				eqCounts[digit][bit]++;
			}
		}
	}

	// Находит, какая цифра соответствует контейнеру, используя маски и эталоны.
	private static int FindDigit(ReadOnlySpan<byte> container, IReadOnlyList<bool[]?> masks)
	{
		for (int digit = 0; digit < DigitCount; digit++)
		{
			var mask = masks[digit];
			if (mask is null)
			{
				// Если для цифры нет ключа/маски — пропускаем её.
				continue;
			}

			bool matches = true;
			var targets = EtalonBits[digit];
			for (int bit = 0; bit < BitLength; bit++)
			{
				// Пропускаем биты, не отмеченные маской как значимые.
				if (!mask[bit])
				{
					continue;
				}

				// Если хоть один значимый бит не совпадает с эталоном — цифра не подходит.
				if (GetBit(container, bit) != targets[bit])
				{
					matches = false;
					break;
				}
			}

			if (matches)
			{
				return digit;
			}
		}
		return -1;
	}

	// Конвертирует ключ (байтовый буфер) в булевую маску значимых битов.
	private static bool[]? BuildMask(byte[]? key)
	{
		if (key is null || key.Length == 0)
		{
			return null;
		}

		var mask = new bool[BitLength];
		for (int bit = 0; bit < BitLength; bit++)
		{
			int byteIndex = key.Length - 1 - (bit >> 3);
			int bitOffset = bit & 7;
			mask[bit] = ((key[byteIndex] >> bitOffset) & 1) == 1;
		}

		return mask;
	}

	// Разбивает байт на сотни/десятки/единицы (для представления 0..255 как три цифры).
	private static (int Hundreds, int Tens, int Ones) SplitDigits(byte value)
	{
		int hundreds = value / 100;
		int remainder = value % 100;
		int tens = remainder / 10;
		int ones = remainder % 10;
		return (hundreds, tens, ones);
	}

	// Возвращает значение отдельного бита в буфере, индексируя биты последовательно.
	private static int GetBit(ReadOnlySpan<byte> buffer, int bitIndex)
	{
		int byteIndex = buffer.Length - 1 - (bitIndex >> 3);
		int bitOffset = bitIndex & 7;
		return (buffer[byteIndex] >> bitOffset) & 1;
	}

	// Загружает стего-данные и разбивает их на тройки контейнеров (по BytePerContainer байт).
	private static ContainerTriple[] LoadStegoTriples(string path)
	{
		var data = File.ReadAllBytes(path);
		// Проверяем выравнивание по размеру контейнера.
		if (data.Length % BytePerContainer != 0)
		{
			throw new InvalidOperationException("Stego payload length is not a multiple of the container size.");
		}

		int containerCount = data.Length / BytePerContainer;
		// Каждый исходный байт закодирован в трёх контейнерах.
		if (containerCount % 3 != 0)
		{
			throw new InvalidOperationException("Stego payload does not align to groups of three containers per byte.");
		}

		var triples = new ContainerTriple[containerCount / 3];
		int offset = 0;
		for (int i = 0; i < triples.Length; i++)
		{
			var first = new byte[BytePerContainer];
			Buffer.BlockCopy(data, offset, first, 0, BytePerContainer);
			offset += BytePerContainer;

			var second = new byte[BytePerContainer];
			Buffer.BlockCopy(data, offset, second, 0, BytePerContainer);
			offset += BytePerContainer;

			var third = new byte[BytePerContainer];
			Buffer.BlockCopy(data, offset, third, 0, BytePerContainer);
			offset += BytePerContainer;

			triples[i] = new ContainerTriple(first, second, third);
		}

		return triples;
	}

	// Преобразует строковые эталоны в массивы int для быстрого сравнения.
	private static int[][] BuildEtalonBits()
	{
		var bits = new int[DigitCount][];
		for (int i = 0; i < DigitCount; i++)
		{
			bits[i] = new int[BitLength];
			for (int j = 0; j < BitLength; j++)
			{
				bits[i][j] = Etalons[i][j] == '1' ? 1 : 0;
			}
		}

		return bits;
	}

	// Сохраняет ключи в бинарном файле с заголовком (магическое число, количество ключей и BitLength).
	private static void SaveKeyFile(IReadOnlyList<byte[]> keys, string path)
	{
		using var fs = File.Create(path);
		using var writer = new BinaryWriter(fs, Utf8, leaveOpen: false);
		writer.Write(KeyMagic);
		writer.Write(keys.Count);
		writer.Write(BitLength);

		foreach (var key in keys)
		{
			var keyBytes = key ?? Array.Empty<byte>();
			writer.Write(keyBytes.Length);
			writer.Write(keyBytes);
		}
	}

	// Убедиться, что директория существует (создать при необходимости).
	private static void EnsureDirectory(string? directory)
	{
		if (string.IsNullOrWhiteSpace(directory))
		{
			return;
		}

		Directory.CreateDirectory(directory);
	}
}

public readonly record struct ContainerTriple(byte[] First, byte[] Second, byte[] Third)
{
	// Возвращает ReadOnlySpan над нужным контейнером (по индексу 0..2).
	public ReadOnlySpan<byte> GetSpan(int index) => index switch
	{
		0 => First,
		1 => Second,
		2 => Third,
		_ => throw new ArgumentOutOfRangeException(nameof(index))
	};
}

// Тип результата восстановления: текст фрагмента, байты, стартовый индекс, ключи и декодированные байты.
public sealed record RecoverResult(
	string FragmentText,
	byte[] FragmentBytes,
	int StartIndex,
	byte[][] Keys,
	byte[] DecodedBytes);

// Измеряет две горячие операции: восстановление ключей и декодирование с ключами.
[MemoryDiagnoser]
public class StegoBenchmarks
{
	// Экземпляр декриптора, используемый в бенчмарках.
	private StegoDecryptor? _decryptor;
	private IReadOnlyList<ContainerTriple> _triples = Array.Empty<ContainerTriple>();
	private byte[] _fragmentBytes = Array.Empty<byte>();
	private byte[][] _keys = Array.Empty<byte[]>();

	// Подготовка: читаем опции из окружения, создаём декриптор и получаем один результат восстановления.
	[GlobalSetup]
	public void Setup()
	{
		var resolvedOptions = BenchmarkOptionsBridge.Read();
		_decryptor = new StegoDecryptor(resolvedOptions);
		var result = _decryptor.Recover(CancellationToken.None);
		_triples = _decryptor.Triples;
		_fragmentBytes = result.FragmentBytes;
		_keys = result.Keys;
	}

	// Бенчмарк: измеряет RecoverKeysFromPlain.
	[Benchmark]
	public byte[][] RecoverKeys() => StegoDecryptor.RecoverKeysFromPlain(_triples, _fragmentBytes);

	// Бенчмарк: измеряет DecodeWithKeys.
	[Benchmark]
	public byte[] DecodePlaintext() => StegoDecryptor.DecodeWithKeys(_triples, _keys);
}

// Мост для передачи опций в/из переменных окружения при запуске бенчмарков.
internal static class BenchmarkOptionsBridge
{
	private const string BookVar = "RECOVER_BOOK_PATH";
	private const string StegoVar = "RECOVER_STEGO_PATH";
	private const string TextVar = "RECOVER_TEXT_OUT";
	private const string RawVar = "RECOVER_RAW_OUT";
	private const string KeyVar = "RECOVER_KEY_OUT";
	private const string InfoVar = "RECOVER_INFO_OUT";
	private const string CharLenVar = "RECOVER_CHAR_LEN";
	private const string DegreeVar = "RECOVER_MAX_DEGREE";

	// Пишет опции в переменные окружения (для передачи в контекст бенчмарка).
	public static void Write(RecoverOptions options)
	{
		Environment.SetEnvironmentVariable(BookVar, options.BookPath);
		Environment.SetEnvironmentVariable(StegoVar, options.StegoPath);
		Environment.SetEnvironmentVariable(TextVar, options.TextOutPath);
		Environment.SetEnvironmentVariable(RawVar, options.RawOutPath);
		Environment.SetEnvironmentVariable(KeyVar, options.KeyOutPath);
		Environment.SetEnvironmentVariable(InfoVar, options.InfoOutPath);
		Environment.SetEnvironmentVariable(CharLenVar, options.FragmentCharLength.ToString());
		Environment.SetEnvironmentVariable(DegreeVar, options.MaxDegreeOfParallelism?.ToString() ?? string.Empty);
	}

	// Читает опции из переменных окружения и возвращает RecoverOptions.
	public static RecoverOptions Read()
	{
		var options = RecoverOptions.Default;

		options = Update(options, BookVar, (opt, value) => opt with { BookPath = value });
		options = Update(options, StegoVar, (opt, value) => opt with { StegoPath = value });
		options = Update(options, TextVar, (opt, value) => opt with { TextOutPath = value });
		options = Update(options, RawVar, (opt, value) => opt with { RawOutPath = value });
		options = Update(options, KeyVar, (opt, value) => opt with { KeyOutPath = value });
		options = Update(options, InfoVar, (opt, value) => opt with { InfoOutPath = value });

		var charLen = Environment.GetEnvironmentVariable(CharLenVar);
		if (int.TryParse(charLen, out var parsedLen) && parsedLen > 0)
		{
			options = options with { FragmentCharLength = parsedLen };
		}

		var degree = Environment.GetEnvironmentVariable(DegreeVar);
		if (int.TryParse(degree, out var parsedDegree) && parsedDegree > 0)
		{
			options = options with { MaxDegreeOfParallelism = parsedDegree };
		}

		return options;

		static RecoverOptions Update(RecoverOptions current, string variable, Func<RecoverOptions, string, RecoverOptions> updater)
		{
			var value = Environment.GetEnvironmentVariable(variable);
			if (string.IsNullOrWhiteSpace(value))
			{
				return current;
			}

			return updater(current, value);
		}
	}
}
