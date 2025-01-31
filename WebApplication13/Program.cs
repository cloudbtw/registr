using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

// Настройка CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins", policy =>
    {
        policy.AllowAnyOrigin() // Разрешить запросы с любого origin
              .AllowAnyMethod() // Разрешить все HTTP-методы (GET, POST, PUT и т.д.)
              .AllowAnyHeader(); // Разрешить все заголовки
    });
});

// Настройка JWT
var jwtKey = "your_256_bit_secret_key_here_1234567890ABCDEF"; // 256-битный ключ (32 символа)
var jwtIssuer = "your_issuer_here"; // Замените на вашего издателя
var jwtAudience = "your_audience_here"; // Замените на вашу аудиторию

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();

// Использование InMemoryDatabase
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseInMemoryDatabase("SimpleAuthDb"));

var app = builder.Build();

// Включаем CORS
app.UseCors("AllowAllOrigins");

app.UseAuthentication();
app.UseAuthorization();

// Регистрация
app.MapPost("/register", async (User user, AppDbContext db) =>
{
    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Ok();
});

// Вход
app.MapPost("/login", async (LoginModel login, AppDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Login == login.Login && u.Password == login.Password);
    if (user == null)
        return Results.Unauthorized();

    var token = GenerateJwtToken(user);
    return Results.Ok(new { token });
});

// Просмотр своего профиля
app.MapGet("/me", async (HttpContext context, AppDbContext db) =>
{
    var login = context.User.Identity.Name;
    var user = await db.Users.FirstOrDefaultAsync(u => u.Login == login);
    if (user == null)
        return Results.NotFound();

    return Results.Ok(new { user.FullName, user.Group, user.Gender, user.Login });
}).RequireAuthorization();

// Просмотр списка пользователей
app.MapGet("/users", async (AppDbContext db) =>
{
    var users = await db.Users.Select(u => new { u.FullName, u.Group }).ToListAsync();
    return Results.Ok(users);
}).RequireAuthorization();

app.Run();

// Генерация JWT-токена
string GenerateJwtToken(User user)
{
    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(jwtIssuer, jwtAudience, null, expires: DateTime.Now.AddMinutes(30), signingCredentials: credentials);
    return new JwtSecurityTokenHandler().WriteToken(token);
}

// Модель пользователя
public class User
{
    [Key]
    public int Id { get; set; }
    public string FullName { get; set; }
    public string Group { get; set; }
    public string Gender { get; set; }
    public string Login { get; set; }
    public string Password { get; set; }
}

// Модель для входа
public class LoginModel
{
    public string Login { get; set; }
    public string Password { get; set; }
}

// Контекст базы данных
public class AppDbContext : DbContext
{
    public DbSet<User> Users { get; set; }

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}