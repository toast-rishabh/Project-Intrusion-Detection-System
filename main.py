import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import time

print("INTRUSION DETECTION SYSTEM PROJECT","\n")
print(os.listdir('C:\\Users\\acer\\PycharmProjects\\IDS_project'))
print()
print("Now printing KDD NAMES","\n")

with open("C:\\Users\\acer\\PycharmProjects\\IDS_project\\kdd.names.txt", 'r') as f:
    print(f.read())
    print()
    print()

cols = """duration,
protocol_type,
service,
flag,
src_bytes,
dst_bytes,
land,
wrong_fragment,
urgent,
hot, 
num_failed_logins,
logged_in,
num_compromised,
root_shell,
su_attempted,
num_root,
num_file_creations,
num_shells,
num_access_files,
num_outbound_cmds,
is_host_login,
is_guest_login,
count,
srv_count,
serror_rate,
srv_serror_rate,
rerror_rate,
srv_rerror_rate,
same_srv_rate,
diff_srv_rate,
srv_diff_host_rate,
dst_host_count,
dst_host_srv_count,
dst_host_same_srv_rate,
dst_host_diff_srv_rate,
dst_host_same_src_port_rate,
dst_host_srv_diff_host_rate,
dst_host_serror_rate,
dst_host_srv_serror_rate,
dst_host_rerror_rate,
dst_host_srv_rerror_rate"""

columns = []
for c in cols.split(','):
    if c.strip():
        columns.append(c.strip())

columns.append('target')
print(len(columns))

with open("C:\\Users\\acer\\PycharmProjects\\IDS_project\\training_attack_types.txt", 'r') as f:
    print(f.read())

attacks_types = {
    'normal': 'normal',
    'back': 'dos',
    'buffer_overflow': 'u2r',
    'ftp_write': 'r2l',
    'guess_passwd': 'r2l',
    'imap': 'r2l',
    'ipsweep': 'probe',
    'land': 'dos',
    'loadmodule': 'u2r',
    'multihop': 'r2l',
    'neptune': 'dos',
    'nmap': 'probe',
    'perl': 'u2r',
    'phf': 'r2l',
    'pod': 'dos',
    'portsweep': 'probe',
    'rootkit': 'u2r',
    'satan': 'probe',
    'smurf': 'dos',
    'spy': 'r2l',
    'teardrop': 'dos',
    'warezclient': 'r2l',
    'warezmaster': 'r2l',
}

path = "C:\\Users\\acer\\PycharmProjects\\IDS_project\\kddcup.data_10_percent.gz"
df = pd.read_csv(path, names=columns)

'''Adding_Attack_Type_column'''
df['Attack Type'] = df.target.apply(lambda r: attacks_types[r[:-1]])

print(df.head(),"\n")

print(df.shape, "\n")

print(df['target'].value_counts())

print("\n", df['Attack Type'].value_counts())

print("\n", df.dtypes)

print("\n", df.isnull().sum())
'''Finding categorical features'''
num_cols = df._get_numeric_data().columns

cate_cols = list(set(df.columns)-set(num_cols))
cate_cols.remove('target')
cate_cols.remove('Attack Type')

print(cate_cols,"\n")
'''Visualization'''
def bar_graph(feature):
    df[feature].value_counts().plot(kind="bar")
    plt.show()
bar_graph('protocol_type')
bar_graph('service')
bar_graph('flag')
bar_graph('logged_in')
bar_graph('target')
bar_graph('Attack Type')
print(df.columns,"\n")

df = df.dropna('columns')
'''# drop columns with NaN'''

df = df[[col for col in df if df[col].nunique() > 1]]
''' keep columns where there are more than 1 unique values'''

corr = df.corr()

plt.figure(figsize=(15, 12))

sns.heatmap(corr)

plt.show()
print(df['num_root'].corr(df['num_compromised']),"\n")
print(df['srv_serror_rate'].corr(df['serror_rate']),"\n")
print(df['srv_count'].corr(df['count']),"\n")
print(df['srv_rerror_rate'].corr(df['rerror_rate']),"\n")
print(df['dst_host_same_srv_rate'].corr(df['dst_host_srv_count']),"\n")
print(df['dst_host_srv_serror_rate'].corr(df['dst_host_serror_rate']),"\n")
print(df['dst_host_srv_rerror_rate'].corr(df['dst_host_rerror_rate']),"\n")
print(df['dst_host_same_srv_rate'].corr(df['same_srv_rate']),"\n")
print(df['dst_host_srv_count'].corr(df['same_srv_rate']),"\n")
print(df['dst_host_same_src_port_rate'].corr(df['srv_count']),"\n")
print(df['dst_host_serror_rate'].corr(df['serror_rate']),"\n")
print(df['dst_host_serror_rate'].corr(df['srv_serror_rate']),"\n")
print(df['dst_host_srv_serror_rate'].corr(df['serror_rate']),"\n")
print(df['dst_host_srv_serror_rate'].corr(df['srv_serror_rate']),"\n")
print(df['dst_host_rerror_rate'].corr(df['rerror_rate']),"\n")
print(df['dst_host_rerror_rate'].corr(df['srv_rerror_rate']),"\n")
print(df['dst_host_srv_rerror_rate'].corr(df['rerror_rate']),"\n")
print(df['dst_host_srv_rerror_rate'].corr(df['srv_rerror_rate']),"\n")
'''This variable is highly correlated with num_compromised and should be ignored for analysis.
(Correlation = 0.9938277978738366)'''
df.drop('num_root', axis=1, inplace=True)
'''
#This variable is highly correlated with serror_rate and should be ignored for analysis.
#(Correlation = 0.9983615072725952)'''
df.drop('srv_serror_rate', axis=1, inplace=True)
'''
#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9947309539817937) '''
df.drop('srv_rerror_rate', axis=1, inplace=True)
'''
#This variable is highly correlated with srv_serror_rate and should be ignored for analysis.
#(Correlation = 0.9993041091850098) '''
df.drop('dst_host_srv_serror_rate', axis=1, inplace=True)
'''
#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9869947924956001)'''
df.drop('dst_host_serror_rate', axis=1, inplace=True)
'''
#This variable is highly correlated with srv_rerror_rate and should be ignored for analysis.
#(Correlation = 0.9821663427308375)'''
df.drop('dst_host_rerror_rate', axis=1, inplace=True)
'''
#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9851995540751249)'''
df.drop('dst_host_srv_rerror_rate', axis=1, inplace=True)
'''
#This variable is highly correlated with dst_host_srv_count and should be ignored for analysis.
#(Correlation = 0.9865705438845669)'''
df.drop('dst_host_same_srv_rate', axis=1, inplace=True)
print(df.head(),"\n")
print(df.shape,"\n")
print(df.columns,"\n")
df_std = df.std()
df_std = df_std.sort_values(ascending=True)
print(df_std,"\n")
print(df['protocol_type'].value_counts(),"\n")
pmap = {'icmp': 0, 'tcp': 1, 'udp': 2}
df['protocol_type'] = df['protocol_type'].map(pmap)
print(df['flag'].value_counts(),"\n")
fmap = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5 , 'S1': 6 , 'S2': 7, 'RSTOS0': 8, 'S3': 9 , 'OTH': 10}
df['flag'] = df['flag'].map(fmap)
print(df.head(),"\n")
df.drop('service', axis=1, inplace=True)
print(df.shape,"\n")
print(df.head(),"\n")
print(df.dtypes,"\n")

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score
df = df.drop(['target', ], axis=1)
print(df.shape,"\n")

# Target variable and train set
Y = df[['Attack Type']]
X = df.drop(['Attack Type', ], axis=1)

sc = MinMaxScaler()
X = sc.fit_transform(X)

# Split test and train data
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.33, random_state=42)
print(X_train.shape,"\n", X_test.shape)
print(Y_train.shape,"\n", Y_test.shape,"\n","\n")

# Gaussian Naive Bayes
print("Gaussian Naive Bayes")
from sklearn.naive_bayes import GaussianNB
model1 = GaussianNB()
start_time = time.time()
model1.fit(X_train, Y_train.values.ravel())
end_time = time.time()
a1 = end_time-start_time
print("Training time: ", a1)
start_time = time.time()
Y_test_pred1 = model1.predict(X_test)
end_time = time.time()
b1 = end_time-start_time
print("Testing time: ", b1)
c1 = model1.score(X_train, Y_train)
print("Train score is:", c1)
d1 = model1.score(X_test,Y_test)
print("Test score is:", d1)
print()
names = ['Training Time', 'Testing Time']
names1=['Train Score', 'Test Score']
values = [a1, b1]
values1= [c1, d1]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.bar(names, values)
f.savefig('time_figure.png', bbox_inches='tight')
plt.show()
plt.bar(names1, values1)
f.savefig('Score_figure.png', bbox_inches='tight')
plt.show()

print("Decision Tree")
from sklearn.tree import DecisionTreeClassifier
model2 = DecisionTreeClassifier(criterion="entropy", max_depth = 4)
start_time = time.time()
model2.fit(X_train, Y_train.values.ravel())
end_time = time.time()
a2 = end_time-start_time
print("Training time: ", a2)
start_time = time.time()
Y_test_pred2 = model2.predict(X_test)
end_time = time.time()
b2 = end_time-start_time
print("Testing time: ", b2)
c2 = model2.score(X_train, Y_train)
print("Train score is:", c2)
d2 = model2.score(X_test,Y_test)
print("Test score is:", d2)
print()
names = ['Training Time', 'Testing Time']
names1=['Train Score', 'Test Score']
values = [a2, b2]
values1= [c2, d2]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.bar(names, values)
f.savefig('time_figure.png', bbox_inches='tight')
plt.show()
plt.bar(names1, values1)
f.savefig('Score_figure.png', bbox_inches='tight')
plt.show()


print("Random Forest")
from sklearn.ensemble import RandomForestClassifier
model3 = RandomForestClassifier(n_estimators=30)
start_time = time.time()
model3.fit(X_train, Y_train.values.ravel())
end_time = time.time()
a3 = end_time-start_time
print("Training time: ", a3)
start_time = time.time()
Y_test_pred3 = model3.predict(X_test)
end_time = time.time()
b3 = end_time-start_time
print("Testing time: ",b3)
c3 = model3.score(X_train, Y_train)
print("Train score is:", c3)
d3 = model3.score(X_test,Y_test)
print("Test score is:", d3)
print()
names = ['Training Time', 'Testing Time']
names1=['Train Score', 'Test Score']
values = [a3, b3]
values1= [c3, d3]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.bar(names, values)
f.savefig('time_figure.png', bbox_inches='tight')
plt.show()
plt.bar(names1, values1)
f.savefig('Score_figure.png', bbox_inches='tight')
plt.show()


print("SVM")
from sklearn.svm import SVC
model4 = SVC(gamma = 'scale')
start_time = time.time()
model4.fit(X_train, Y_train.values.ravel())
end_time = time.time()
a4 = end_time-start_time
print("Training time: ", a4)
start_time = time.time()
Y_test_pred4 = model4.predict(X_test)
end_time = time.time()
b4 = end_time-start_time
print("Testing time: ", b4)
c4 = model4.score(X_train, Y_train)
print("Train score is:", c4)
d4 = model4.score(X_test,Y_test)
print("Test score is:", d4)
print()
names = ['Training Time', 'Testing Time']
names1=['Train Score', 'Test Score']
values = [a4, b4]
values1= [c4, d4]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.bar(names, values)
f.savefig('time_figure.png', bbox_inches='tight')
plt.show()
plt.bar(names1, values1)
f.savefig('Score_figure.png', bbox_inches='tight')
plt.show()


print("Logistic Regression")
from sklearn.linear_model import LogisticRegression
model5 = LogisticRegression(max_iter=1200000)
start_time = time.time()
model5.fit(X_train, Y_train.values.ravel())
end_time = time.time()
a5 = end_time-start_time
print("Training time: ", a5)
start_time = time.time()
Y_test_pred5 = model5.predict(X_test)
end_time = time.time()
b5 = end_time-start_time
print("Testing time: ", b5)
c5 = model5.score(X_train, Y_train)
print("Train score is:", c5)
d5 = model5.score(X_test,Y_test)
print("Test score is:", d5)
print()
names = ['Training Time', 'Testing Time']
names1=['Train Score', 'Test Score']
values = [a5, b5]
values1= [c5, d5]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.bar(names, values)
f.savefig('time_figure.png', bbox_inches='tight')
plt.show()
plt.bar(names1, values1)
f.savefig('Score_figure.png', bbox_inches='tight')
plt.show()


print("Gradient Boosting")
from sklearn.ensemble import GradientBoostingClassifier
model6 = GradientBoostingClassifier(random_state=0)
start_time = time.time()
model6.fit(X_train, Y_train.values.ravel())
end_time = time.time()
a6 = end_time-start_time
print("Training time: ", a6)
start_time = time.time()
Y_test_pred6 = model6.predict(X_test)
end_time = time.time()
b6 = end_time-start_time
print("Testing time: ", b6)
c6 = model6.score(X_train, Y_train)
print("Train score is:", c6)
d6 = model6.score(X_test,Y_test)
print("Test score is:", d6)
print()
names = ['Training Time', 'Testing Time']
names1=['Train Score', 'Test Score']
values = [a6, b6]
values1= [c6, d6]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.bar(names, values)
f.savefig('time_figure.png', bbox_inches='tight')
plt.show()
plt.bar(names1, values1)
f.savefig('Score_figure.png', bbox_inches='tight')
plt.show()


from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier
def fun():
    model = Sequential()

    '''#here 30 is output dimension'''
    model.add(Dense(30,input_dim =30,activation = 'relu',kernel_initializer='random_uniform'))

    '''#in next layer we do not specify the input_dim as the model is sequential so output of previous layer is input to next layer'''
    model.add(Dense(1,activation='sigmoid',kernel_initializer='random_uniform'))

    '''#5 classes-normal,dos,probe,r2l,u2r'''
    model.add(Dense(5,activation='softmax'))

    '''#loss is categorical_crossentropy which specifies that we have multiple classe'''

    model.compile(loss ='categorical_crossentropy',optimizer = 'adam',metrics = ['accuracy'])

    return model
'''#Since,the dataset is very big and we cannot fit complete data at once so we use batch size.
#This divides our data into batches each of size equal to batch_size.
#Now only this number of samples will be loaded into memory and processed.
#Once we are done with one batch it is flushed from memory and the next batch will be processed.'''
model7 = KerasClassifier(build_fn=fun,epochs=100,batch_size=64)
print("ANN")
start = time.time()
model7.fit(X_train, Y_train.values.ravel())
end = time.time()
print('Training time')
a7 = (end-start)
print(a7)
start_time = time.time()
Y_test_pred7 = model7.predict(X_test)
end_time = time.time()
b7 = end_time-start_time
print("Testing time: ", b7)
start_time = time.time()
Y_train_pred7 = model7.predict(X_train)
end_time = time.time()
c7 = accuracy_score(Y_train,Y_train_pred7)
print(c7)
d7 = accuracy_score(Y_test,Y_test_pred7)
print(d7)
print()
names = ['Training Time', 'Testing Time']
names1=['Train Score', 'Test Score']
values = [a7, b7]
values1= [c7, d7]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.bar(names, values)
f.savefig('time_figure.png', bbox_inches='tight')
plt.show()
plt.bar(names1, values1)
f.savefig('Score_figure.png', bbox_inches='tight')
plt.show()



'''#TRAINING ACCURACY'''
names = ['NB','DT', 'RF', 'SVM', 'LR', 'GB', 'ANN']
values = [87.951, 99.058, 99.997, 99.875, 99.352, 99.793, 99.896]
f = plt.figure(figsize=(15,3),num=10)
plt.subplot(131)
plt.ylim(80, 102)
plt.bar(names, values)
f.savefig('test_accuracy_figure.png', bbox_inches='tight')
plt.show()

'''TRAINING ACCURACY'''
names = ['NB', 'DT', 'RF', 'SVM', 'LR', 'GB', 'ANN']
values = [87.903, 99.052, 99.969, 99.879, 99.352, 99.771, 99.860]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.ylim(80, 102)
plt.bar(names, values)
f.savefig('test_accuracy_figure.png', bbox_inches='tight')
plt.show()

'''#TRAINING TIME'''
names = ['NB', 'DT', 'RF', 'SVM', 'LR', 'GB', 'ANN']
values = [a1, a2, a3, a4, a5, a6, a7]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.bar(names, values)
f.savefig('train_time_figure.png', bbox_inches='tight')
plt.show()

'''#TESTING TIME'''
names = ['NB', 'DT', 'RF', 'SVM', 'LR', 'GB', 'ANN']
values = [b1, b2, b3, b4, b5, b6, b7]
f = plt.figure(figsize=(15, 3), num=10)
plt.subplot(131)
plt.bar(names, values)
f.savefig('test_time_figure.png', bbox_inches='tight')
plt.show()
