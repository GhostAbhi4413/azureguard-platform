using System.Text;
using ApplicationLayer;
using BusinessLayer;
using DataAccessLayer;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddScoped<ScannerReportParser>();
builder.Services.AddCors(o => o.AddPolicy("Frontend", p => p.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin()));
builder.Services.AddHttpClient<RepositoryAnalyzer>();
builder.Services.Configure<JenkinsOptions>(builder.Configuration.GetSection("Jenkins"));
builder.Services.AddHttpClient<JenkinsService>();

// Add services to the container.

builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))); builder.Services.AddScoped<PasswordService>(); builder.Services.AddScoped<AuthService>(); builder.Services.AddScoped<ReleaseService>(); builder.Services.AddScoped<RiskPolicyEngine>(); builder.Services.AddScoped(typeof(IRepository<>), typeof(Repository<>)); var key = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!); builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o => o.TokenValidationParameters = new TokenValidationParameters { ValidateIssuer = true, ValidIssuer = builder.Configuration["Jwt:Issuer"], ValidateAudience = true, ValidAudience = builder.Configuration["Jwt:Audience"], ValidateIssuerSigningKey = true, IssuerSigningKey = new SymmetricSecurityKey(key), ValidateLifetime = true }); builder.Services.AddAuthorization(); builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseCors("Frontend");

app.UseAuthentication(); app.UseAuthorization();

app.MapControllers();

app.Run();
